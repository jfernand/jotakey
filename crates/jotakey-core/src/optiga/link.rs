// (c) Javier Fernandez @ JotaSoft 2026
//! The master's data link (IFX I2C protocol §3), with the network and transport header
//! (§4, §5): one packet out, one packet back.
//!
//! The window is one frame (`WIN_SIZE` = 1): the master sends a data frame and reads frames
//! until the OPTIGA's data frame answering it arrives, then acknowledges that with a control
//! frame. Frame numbers count modulo 4 from 3, as in Infineon's host library, so the first
//! data frame is number 0. A frame lost or refused is sent again at most [`TRANS_REPEAT`]
//! times; every wait is bounded by a poll budget, so [`Link::transceive`] always returns.
//!
//! Each packet starts with the PCTR byte: bits 7:4 the channel (always 0 here), bit 3 the
//! presentation layer's presence, bits 2:0 chaining. This driver's APDUs all fit in one
//! packet, so it never chains, and a chained packet from the OPTIGA is refused.

use super::frame::{self, Ack, FRAME_NUMBER_MASK, FRAME_SIZE, Frame};
use super::physical::{self, REG_DATA};
use super::{I2c, OptigaError};

/// How often a frame is sent before the link gives up (`DL_TRANS_REPEAT`).
pub const TRANS_REPEAT: u32 = 3;
/// Poll interval while waiting for a frame.
pub const POLL_INTERVAL_US: u32 = 1000;
/// Polls before an unacknowledged frame is sent again (`PL_TRANS_TIMEOUT_MS` = 10 ms).
pub const ACK_POLLS: u32 = 10;
/// Polls before an acknowledged command counts as unanswered: 8 s, more than the longest
/// throttled command (the security monitor delays protected operations by up to 5 s).
pub const RESPONSE_POLLS: u32 = 8000;

/// PCTR bit 3: the presentation layer is present.
pub const PCTR_PRESENTATION: u8 = 0x08;
const PCTR_CHANNEL_MASK: u8 = 0xF0;
const PCTR_CHAIN_MASK: u8 = 0x07;

/// Split a received packet into its presentation flag and body.
///
/// # Errors
/// [`OptigaError::Malformed`] for another channel, chaining, or a packet without a body.
pub fn split_packet(packet: &[u8]) -> Result<(bool, &[u8]), OptigaError> {
    let (&pctr, body) = packet.split_first().ok_or(OptigaError::Malformed)?;
    if pctr & (PCTR_CHANNEL_MASK | PCTR_CHAIN_MASK) != 0 || body.is_empty() {
        return Err(OptigaError::Malformed);
    }
    Ok((pctr & PCTR_PRESENTATION != 0, body))
}

/// What one wait for the answer produced.
enum Wait {
    /// The answering packet, copied to the caller's buffer (its length).
    Packet(usize),
    /// Our frame was refused or never acknowledged: send it again.
    Resend,
}

/// The master side of the data link.
#[derive(Clone, Debug)]
pub struct Link {
    tx: u8,
    rx: u8,
    frame_size: usize,
}

impl Link {
    /// A link with frames of `frame_size` bytes (as negotiated, at most [`FRAME_SIZE`]).
    #[must_use]
    pub fn new(frame_size: usize) -> Self {
        Self { tx: FRAME_NUMBER_MASK, rx: FRAME_NUMBER_MASK, frame_size: frame_size.min(FRAME_SIZE) }
    }

    /// Send `packet` (PCTR included) and return the length of the OPTIGA's answering packet,
    /// copied into `resp`.
    ///
    /// # Errors
    /// [`OptigaError::Length`] if `packet` does not fit a frame or the answer does not fit
    /// `resp`; [`OptigaError::Resync`] if the OPTIGA reset the link;
    /// [`OptigaError::Timeout`] if no answer came within the retry budget;
    /// [`OptigaError::Bus`] on a bus failure.
    pub fn transceive<B: I2c>(&mut self, bus: &mut B, packet: &[u8], resp: &mut [u8]) -> Result<usize, OptigaError> {
        let mut out = [0u8; FRAME_SIZE];
        let max_packet = self.frame_size.checked_sub(frame::OVERHEAD).ok_or(OptigaError::Length)?;
        if packet.len() > max_packet {
            return Err(OptigaError::Length);
        }
        let number = self.tx.wrapping_add(1) & FRAME_NUMBER_MASK;
        let n = frame::encode_data(number, self.rx, packet, &mut out)?;
        self.tx = number;
        let sent = out.get(..n).ok_or(OptigaError::Length)?;
        for _ in 0..TRANS_REPEAT {
            physical::write_register(bus, REG_DATA, sent)?;
            match self.wait(bus, resp)? {
                Wait::Packet(len) => return Ok(len),
                Wait::Resend => {}
            }
        }
        Err(OptigaError::Timeout)
    }

    fn send_control<B: I2c>(&self, bus: &mut B, ack_number: u8, ack: Ack) -> Result<(), OptigaError> {
        physical::write_register(bus, REG_DATA, &frame::encode_control(ack_number, ack))
    }

    /// Read frames until the answer to frame `self.tx` arrives.
    fn wait<B: I2c>(&mut self, bus: &mut B, resp: &mut [u8]) -> Result<Wait, OptigaError> {
        let mut acked = false;
        let mut polls: u32 = 0;
        let mut buf = [0u8; FRAME_SIZE];
        loop {
            let budget = if acked { RESPONSE_POLLS } else { ACK_POLLS };
            if polls >= budget {
                return if acked { Err(OptigaError::Timeout) } else { Ok(Wait::Resend) };
            }
            polls = polls.saturating_add(1);
            let st = physical::state(bus)?;
            let len = usize::from(st.length);
            if !st.response_ready || len == 0 {
                bus.delay_us(POLL_INTERVAL_US);
                continue;
            }
            if len > self.frame_size {
                // Longer than agreed: the OPTIGA is not following the protocol.
                return Err(OptigaError::Malformed);
            }
            let rx_frame = buf.get_mut(..len).ok_or(OptigaError::Malformed)?;
            physical::read_register(bus, REG_DATA, rx_frame)?;
            match frame::decode(rx_frame) {
                Err(_) => {
                    // Damaged: NAK the next expected frame (§3.4.1).
                    self.send_control(bus, self.rx.wrapping_add(1) & FRAME_NUMBER_MASK, Ack::Nak)?;
                }
                Ok(Frame::Resync) => {
                    self.tx = FRAME_NUMBER_MASK;
                    self.rx = FRAME_NUMBER_MASK;
                    return Err(OptigaError::Resync);
                }
                Ok(Frame::Control { ack_number, ack }) => {
                    if ack_number == self.tx {
                        match ack {
                            Ack::Ack => acked = true,
                            Ack::Nak => return Ok(Wait::Resend),
                        }
                    }
                }
                Ok(Frame::Data { number, ack_number, ack, packet }) => {
                    let expected = self.rx.wrapping_add(1) & FRAME_NUMBER_MASK;
                    if number == expected && ack_number == self.tx && ack == Ack::Ack {
                        let dst = resp.get_mut(..packet.len()).ok_or(OptigaError::Length)?;
                        dst.copy_from_slice(packet);
                        self.rx = number;
                        self.send_control(bus, number, Ack::Ack)?;
                        return Ok(Wait::Packet(packet.len()));
                    }
                    if ack == Ack::Nak && ack_number == self.tx {
                        return Ok(Wait::Resend);
                    }
                    if number == self.rx {
                        // A repeat of the frame already accepted: our ACK was lost.
                        self.send_control(bus, self.rx, Ack::Ack)?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_are_split_strictly() {
        assert_eq!(split_packet(&[0x00, 1, 2]), Ok((false, &[1u8, 2][..])));
        assert_eq!(split_packet(&[0x08, 0x23]), Ok((true, &[0x23u8][..])));
        assert_eq!(split_packet(&[]), Err(OptigaError::Malformed));
        assert_eq!(split_packet(&[0x00]), Err(OptigaError::Malformed), "no body");
        assert_eq!(split_packet(&[0x10, 1]), Err(OptigaError::Malformed), "channel 1");
        for chain in [0x01, 0x02, 0x04, 0x07] {
            assert_eq!(split_packet(&[chain, 1]), Err(OptigaError::Malformed), "chained");
        }
    }

    use crate::optiga::BusError;
    use crate::optiga::physical::REG_I2C_STATE;
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// A scripted OPTIGA at the frame level: it presents `frames` in order, whatever the
    /// master sends, and records every frame the master writes. `states` overrides the next
    /// `I2C_STATE` reads.
    #[derive(Default)]
    struct Script {
        frames: VecDeque<Vec<u8>>,
        states: VecDeque<[u8; 4]>,
        sent: Vec<Vec<u8>>,
        reg: u8,
    }

    impl Script {
        fn new(frames: &[Vec<u8>]) -> Self {
            Self { frames: frames.iter().cloned().collect(), ..Self::default() }
        }
        fn data_frames_sent(&self) -> usize {
            self.sent.iter().filter(|f| f[0] & 0x80 == 0).count()
        }
        fn sent_control(&self, f: [u8; 5]) -> bool {
            self.sent.iter().any(|s| s[..] == f[..])
        }
    }

    impl I2c for Script {
        fn write(&mut self, bytes: &[u8]) -> Result<(), BusError> {
            self.reg = bytes[0];
            if bytes.len() > 1 && bytes[0] == REG_DATA {
                self.sent.push(bytes[1..].to_vec());
            }
            Ok(())
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<(), BusError> {
            if self.reg == REG_I2C_STATE {
                let st = self.states.pop_front().unwrap_or_else(|| match self.frames.front() {
                    Some(f) => [0x40, 0, 0, u8::try_from(f.len()).unwrap_or(0xFF)],
                    None => [0, 0, 0, 0],
                });
                buf.copy_from_slice(&st);
            } else {
                let f = self.frames.pop_front().unwrap_or_default();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = f.get(i).copied().unwrap_or(0xFF);
                }
            }
            Ok(())
        }
        fn delay_us(&mut self, _: u32) {}
    }

    fn data(number: u8, ack_number: u8, packet: &[u8]) -> Vec<u8> {
        let mut out = [0u8; FRAME_SIZE];
        let n = frame::encode_data(number, ack_number, packet, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn with_nak(mut f: Vec<u8>) -> Vec<u8> {
        f[0] |= 0x20;
        let body = f.len() - 2;
        let crc = crate::optiga::crc::crc16(&f[..body]).to_be_bytes();
        f[body..].copy_from_slice(&crc);
        f
    }

    fn control(ack_number: u8, ack: Ack) -> Vec<u8> {
        frame::encode_control(ack_number, ack).to_vec()
    }

    fn run(link: &mut Link, bus: &mut Script, packet: &[u8]) -> Result<Vec<u8>, OptigaError> {
        let mut resp = [0u8; FRAME_SIZE];
        link.transceive(bus, packet, &mut resp).map(|n| resp[..n].to_vec())
    }

    #[test]
    fn an_answer_is_taken_and_acknowledged() {
        let mut bus = Script::new(&[control(0, Ack::Ack), data(0, 0, &[0, 1, 2])]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 9]), Ok(std::vec![0, 1, 2]));
        assert_eq!(bus.sent[0], data(0, 3, &[0, 9]), "first data frame is number 0, acking 3");
        assert!(bus.sent_control(frame::encode_control(0, Ack::Ack)), "the answer is acknowledged");
        // The next exchange uses the next numbers.
        bus.frames.push_back(data(1, 1, &[0, 3]));
        assert_eq!(run(&mut link, &mut bus, &[0, 8]), Ok(std::vec![0, 3]));
        assert_eq!(bus.sent[2], data(1, 0, &[0, 8]));
    }

    #[test]
    fn frames_that_do_not_answer_are_skipped() {
        let mut bus = Script::new(&[
            control(2, Ack::Ack),   // acknowledges another frame: ignored
            data(1, 0, &[0, 0xAA]), // not the next frame number
            data(0, 2, &[0, 0xBB]), // acknowledges another frame
            data(3, 0, &[0, 0xCC]), // a repeat of the last frame accepted: re-acked
            data(0, 0, &[0, 0xDD]),
        ]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 0xDD]));
        assert!(bus.sent_control(frame::encode_control(3, Ack::Ack)));
        assert_eq!(bus.data_frames_sent(), 1, "nothing above asked for a resend");
    }

    #[test]
    fn only_a_repeat_is_acknowledged_again() {
        // Frame 1 is neither the next frame (0) nor a repeat of the last accepted one (3).
        let mut bus = Script::new(&[data(1, 0, &[0, 0xAA]), data(0, 0, &[0, 0xDD])]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 0xDD]));
        assert!(!bus.sent_control(frame::encode_control(3, Ack::Ack)), "no ACK for an out-of-window frame");
    }

    #[test]
    fn damaged_frames_are_naked() {
        let mut bad = data(0, 0, &[0, 1]);
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut bus = Script::new(&[bad, data(0, 0, &[0, 2])]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 2]));
        assert!(bus.sent_control(frame::encode_control(0, Ack::Nak)), "NAK for the frame expected next");
    }

    #[test]
    fn a_nak_sends_the_frame_again() {
        let mut bus = Script::new(&[control(0, Ack::Nak), data(0, 0, &[0, 7])]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 7]));
        assert_eq!(bus.data_frames_sent(), 2);
        assert_eq!(bus.sent[0], bus.sent[1], "the same frame, same number");
        // A NAK piggy-backed on a data frame also asks for the frame again.
        let mut bus = Script::new(&[with_nak(data(0, 0, &[0, 5])), data(0, 0, &[0, 6])]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 6]));
        assert_eq!(bus.data_frames_sent(), 2);
        // A NAK for another frame does not.
        let mut bus = Script::new(&[control(2, Ack::Nak), with_nak(data(0, 1, &[0, 5])), data(0, 0, &[0, 6])]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 6]));
        assert_eq!(bus.data_frames_sent(), 1);
    }

    #[test]
    fn an_unacknowledged_frame_is_sent_a_bounded_number_of_times() {
        let mut bus = Script::new(&[]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Err(OptigaError::Timeout));
        assert_eq!(bus.data_frames_sent(), usize::try_from(TRANS_REPEAT).unwrap());
        // Acknowledged but never answered: one send, then the long timeout.
        let mut bus = Script::new(&[control(0, Ack::Ack)]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Err(OptigaError::Timeout));
        assert_eq!(bus.data_frames_sent(), 1);
    }

    #[test]
    fn the_state_register_is_read_strictly() {
        // Ready with length 0, and a stale length without ready: neither is a frame.
        let mut bus = Script::new(&[data(0, 0, &[0, 4])]);
        bus.states.push_back([0x40, 0, 0, 0]);
        bus.states.push_back([0x00, 0, 0, 8]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 4]));
        assert!(!bus.sent.iter().any(|f| f[0] & 0xE0 == 0xA0), "no NAK: nothing was read");
        // Longer than agreed.
        let mut bus = Script::new(&[]);
        bus.states.push_back([0x40, 0, 0x01, 0x16]);
        assert_eq!(run(&mut Link::new(FRAME_SIZE), &mut bus, &[0, 1]), Err(OptigaError::Malformed));
        // Exactly the agreed size is fine.
        let answer = data(0, 0, &[0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(answer.len(), 12);
        let mut bus = Script::new(&[answer]);
        assert_eq!(run(&mut Link::new(12), &mut bus, &[0, 1]), Ok(std::vec![0, 1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn packets_must_fit_the_agreed_frame() {
        let mut bus = Script::new(&[data(0, 0, &[0, 1])]);
        assert!(run(&mut Link::new(12), &mut bus, &[0; 7]).is_ok());
        let mut bus = Script::new(&[data(0, 0, &[0, 1])]);
        assert_eq!(run(&mut Link::new(12), &mut bus, &[0; 8]), Err(OptigaError::Length));
        assert_eq!(run(&mut Link::new(4), &mut bus, &[0; 1]), Err(OptigaError::Length));
        // The answer must fit the caller's buffer.
        let mut bus = Script::new(&[data(0, 0, &[0, 1, 2])]);
        let mut small = [0u8; 2];
        assert_eq!(Link::new(FRAME_SIZE).transceive(&mut bus, &[0, 1], &mut small), Err(OptigaError::Length));
    }

    #[test]
    fn a_resync_from_the_optiga_ends_the_exchange() {
        let mut bus = Script::new(&[frame::encode_resync().to_vec()]);
        let mut link = Link::new(FRAME_SIZE);
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Err(OptigaError::Resync));
        // The counters start over: the next frame is number 0 again.
        bus.frames.push_back(data(0, 0, &[0, 2]));
        assert_eq!(run(&mut link, &mut bus, &[0, 1]), Ok(std::vec![0, 2]));
        assert_eq!(bus.sent.last().map(|f| f[0]), Some(0x80), "acknowledged as frame 0");
        assert_eq!(bus.sent[bus.sent.len() - 2], data(0, 3, &[0, 1]));
    }
}
