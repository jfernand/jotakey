// (c) Javier Fernandez @ JotaSoft 2026
// The webauthn-topcoat relying party on AWS: one Lambda function behind an HTTP API on its
// own domain, with its state in DynamoDB. See ../README.md.
//
// Two stacks, so the stateful one (the table: every registered key) never changes or goes
// away with a redeploy of the stateless one.

import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import { Construct } from 'constructs';

// AWS Lambda Web Adapter 1.1.0 (x86_64), published by AWS in account 753240598075. It runs
// the server unchanged and turns Lambda invocations into HTTP requests on PORT.
const WEB_ADAPTER_LAYER = 30;
const PORT = '8080';

// The relying party's state: accounts, credentials, ceremonies, sessions
// (../src/store/dynamo.rs). Retained and protected: losing it strands every key.
export class StateStack extends cdk.Stack {
  readonly table: dynamodb.TableV2;

  constructor(scope: Construct, id: string, props: cdk.StackProps) {
    super(scope, id, { ...props, terminationProtection: true });
    this.table = new dynamodb.TableV2(this, 'Table', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      timeToLiveAttribute: 'ttl',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
  }
}

export interface AppStackProps extends cdk.StackProps {
  table: dynamodb.ITableV2;
  // The site's name and the WebAuthn RP ID, e.g. jotakey.casaroja.es. Credentials are
  // bound to it: changing it strands every registered key.
  domainName: string;
  // The Route 53 public hosted zone the name lives in.
  hostedZoneId: string;
  zoneName: string;
  // The server binary, target/lambda/webauthn-topcoat (infra/build.sh).
  code: lambda.Code;
}

export class AppStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AppStackProps) {
    super(scope, id, props);
    const { table, domainName } = props;

    const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'Zone', {
      hostedZoneId: props.hostedZoneId,
      zoneName: props.zoneName,
    });
    const certificate = new acm.Certificate(this, 'Certificate', {
      domainName,
      validation: acm.CertificateValidation.fromDns(zone),
    });

    const server = new lambda.Function(this, 'Server', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.X86_64,
      handler: 'bootstrap',
      code: props.code,
      layers: [
        lambda.LayerVersion.fromLayerVersionArn(
          this,
          'WebAdapter',
          `arn:aws:lambda:${this.region}:753240598075:layer:LambdaAdapterLayerX86:${WEB_ADAPTER_LAYER}`,
        ),
      ],
      memorySize: 256,
      timeout: cdk.Duration.seconds(10),
      environment: {
        ORIGIN: `https://${domainName}`,
        DYNAMODB_TABLE: table.tableName,
        // Topcoat listens on PORT; the adapter forwards to AWS_LWA_PORT.
        PORT,
        AWS_LWA_PORT: PORT,
      },
      logGroup: new logs.LogGroup(this, 'ServerLogs', {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });
    // Exactly what src/store/dynamo.rs calls: single-item reads, writes and deletes (a
    // transaction's puts and deletes need PutItem and DeleteItem), and Scan for the list of
    // usernames on the sign-in page. No Query, no table or stream management.
    table.grant(server, 'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem', 'dynamodb:Scan');

    const domain = new apigwv2.DomainName(this, 'Domain', { domainName, certificate });
    const api = new apigwv2.HttpApi(this, 'Api', {
      defaultIntegration: new HttpLambdaIntegration('Server', server),
      defaultDomainMapping: { domainName: domain },
      // Only the custom domain: the origin WebAuthn checks and the cookies' host.
      disableExecuteApiEndpoint: true,
    });
    // Rate limiting, for the whole API (the server has none of its own).
    const stage = api.defaultStage?.node.defaultChild as apigwv2.CfnStage;
    stage.defaultRouteSettings = { throttlingRateLimit: 10, throttlingBurstLimit: 20 };

    new route53.ARecord(this, 'Alias', {
      zone,
      recordName: domainName,
      target: route53.RecordTarget.fromAlias(
        new targets.ApiGatewayv2DomainProperties(domain.regionalDomainName, domain.regionalHostedZoneId),
      ),
    });

    new cdk.CfnOutput(this, 'Url', { value: `https://${domainName}` });
  }
}
