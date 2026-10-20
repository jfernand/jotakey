// (c) Javier Fernandez @ JotaSoft 2026
// Synthesis tests: the properties that would break the demo, or strand its keys, if they
// changed by accident.

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { AppStack, StateStack } from '../lib/stacks';

const env = { account: '123456789012', region: 'us-east-1' };

function synth() {
  const app = new cdk.App();
  const asset = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-asset-'));
  fs.writeFileSync(path.join(asset, 'bootstrap'), '');
  const state = new StateStack(app, 'State', { env });
  const server = new AppStack(app, 'App', {
    env,
    table: state.table,
    domainName: 'jotakey.example.org',
    zoneName: 'example.org',
    hostedZoneId: 'Z0000000000000000000',
    code: lambda.Code.fromAsset(asset),
  });
  return { state: Template.fromStack(state), app: Template.fromStack(server) };
}

const { state, app } = synth();

test('the table keeps its logical ID, is retained and protected', () => {
  // A new logical ID would replace the table: every registered key gone.
  const tables = state.findResources('AWS::DynamoDB::GlobalTable');
  expect(Object.keys(tables)).toEqual([expect.stringMatching(/^Table[0-9A-F]{8}$/)]);
  const [table] = Object.values(tables);
  expect(table.DeletionPolicy).toBe('Retain');
  expect(table.UpdateReplacePolicy).toBe('Retain');
  state.hasResourceProperties('AWS::DynamoDB::GlobalTable', {
    KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
    AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }],
    TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
    Replicas: [Match.objectLike({ DeletionProtectionEnabled: true })],
  });
});

test('the server runs on x86_64 with the web adapter and knows its origin and table', () => {
  app.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'provided.al2023',
    Architectures: ['x86_64'],
    Layers: [Match.stringLikeRegexp(':layer:LambdaAdapterLayerX86:\\d+$')],
    Environment: {
      Variables: Match.objectLike({
        ORIGIN: 'https://jotakey.example.org',
        DYNAMODB_TABLE: Match.anyValue(),
        PORT: '8080',
        AWS_LWA_PORT: '8080',
      }),
    },
  });
});

test('the server may get, put, delete and scan items, nothing more', () => {
  app.hasResourceProperties('AWS::IAM::Policy', {
    PolicyDocument: {
      Statement: [
        Match.objectLike({
          Effect: 'Allow',
          Action: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem', 'dynamodb:Scan'],
        }),
      ],
    },
  });
});

test('the API answers only on the custom domain, throttled', () => {
  app.hasResourceProperties('AWS::ApiGatewayV2::Api', { DisableExecuteApiEndpoint: true });
  app.hasResourceProperties('AWS::ApiGatewayV2::DomainName', { DomainName: 'jotakey.example.org' });
  app.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
    DefaultRouteSettings: { ThrottlingRateLimit: 10, ThrottlingBurstLimit: 20 },
  });
  app.hasResourceProperties('AWS::Route53::RecordSet', { Name: 'jotakey.example.org.', Type: 'A' });
  app.hasResourceProperties('AWS::CertificateManager::Certificate', {
    DomainName: 'jotakey.example.org',
    ValidationMethod: 'DNS',
  });
});
