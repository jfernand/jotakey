#!/usr/bin/env node
// (c) Javier Fernandez @ JotaSoft 2026
// The CDK app: the relying party's state and its server, in us-east-1. Settings come from
// cdk.json's context (domainName, zoneName, hostedZoneId); override with -c key=value.

import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { AppStack, StateStack } from '../lib/stacks';

const app = new cdk.App();
const setting = (key: string): string => {
  const value = app.node.tryGetContext(key);
  if (typeof value !== 'string' || value === '') {
    throw new Error(`missing context ${key} (cdk.json, or -c ${key}=...)`);
  }
  return value;
};
const env = { account: process.env.CDK_DEFAULT_ACCOUNT, region: 'us-east-1' };

const state = new StateStack(app, 'JotakeyRpState', { env });
new AppStack(app, 'JotakeyRp', {
  env,
  table: state.table,
  domainName: setting('domainName'),
  zoneName: setting('zoneName'),
  hostedZoneId: setting('hostedZoneId'),
  code: lambda.Code.fromAsset(path.join(__dirname, '../../target/lambda/webauthn-topcoat')),
});
