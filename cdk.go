package introspector_enclave

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsec2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsecrassets"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awskms"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	"github.com/aws/aws-cdk-go/awscdk/v2/awss3assets"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsssm"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

type NitroIntrospectorStackProps struct {
	awscdk.StackProps
	Deployment   string
	RepoRoot     string
	InstanceType string
	AppName      string
	Secrets      []SecretConfig
}

func NewNitroIntrospectorStack(scope constructs.Construct, id string, props *NitroIntrospectorStackProps) awscdk.Stack {
	deployment := "dev"
	repoRoot := "."
	instanceType := "m6i.xlarge"
	appName := "app"
	var secrets []SecretConfig
	stackProps := awscdk.StackProps{}
	if props != nil {
		stackProps = props.StackProps
		if props.Deployment != "" {
			deployment = props.Deployment
		}
		if props.RepoRoot != "" {
			repoRoot = props.RepoRoot
		}
		if props.InstanceType != "" {
			instanceType = props.InstanceType
		}
		if props.AppName != "" {
			appName = props.AppName
		}
		secrets = props.Secrets
	}

	stack := awscdk.NewStack(scope, jsii.String(id), &stackProps)

	repoPath := func(parts ...string) string {
		return filepath.Join(append([]string{repoRoot}, parts...)...)
	}

	encryptionKey := awskms.NewKey(stack, jsii.String("EncryptionKey"), &awskms.KeyProps{
		EnableKeyRotation: jsii.Bool(true),
	})
	// Retain the KMS key on stack deletion. The key is locked to the enclave's
	// PCR0 after first boot (no PutKeyPolicy for anyone), so CDK cannot call
	// ScheduleKeyDeletion. The destroy command handles key deletion via the
	// EC2 instance role before tearing down the stack.
	encryptionKey.ApplyRemovalPolicy(awscdk.RemovalPolicy_RETAIN)

	outboundProxyImage := awsecrassets.NewDockerImageAsset(stack, jsii.String("gvproxy"), &awsecrassets.DockerImageAssetProps{
		Directory: jsii.String(repoRoot),
		Platform:  awsecrassets.Platform_LINUX_AMD64(),
		File:      jsii.String("enclave/gvproxy/Dockerfile"),
		AssetName: jsii.String("gvisor-tap-vsock"),
		Exclude: &[]*string{
			jsii.String("enclave/cdk.out"),
			jsii.String("enclave/artifacts"),
			jsii.String("flake_result"),
			jsii.String(".git"),
			jsii.String("bin"),
		},
	})

	// The EIF is built by Nix (nix build .#eif) before CDK deploy.
	// Upload the pre-built, reproducible EIF to S3.
	enclaveEif := awss3assets.NewAsset(stack, jsii.String("EnclaveEIF"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave", "artifacts", "image.eif")),
	})

	enclaveInit := awss3assets.NewAsset(stack, jsii.String("AWSNitroEnclaveInit"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave/scripts/enclave_init.sh")),
	})

	enclaveInitSystemd := awss3assets.NewAsset(stack, jsii.String("AWSNitroEnclaveInitService"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave/systemd/enclave-watchdog.service")),
	})

	imdsSystemd := awss3assets.NewAsset(stack, jsii.String("AWSNitroEnclaveIMDSService"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave/systemd/enclave-imds-proxy.service")),
	})

	gvproxySystemd := awss3assets.NewAsset(stack, jsii.String("AWSNitroEnclaveGvproxyService"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave/systemd/gvproxy.service")),
	})

	mgmtBinary := awss3assets.NewAsset(stack, jsii.String("AWSNitroEnclaveMgmtBinary"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave/artifacts/enclave-mgmt")),
	})

	mgmtSystemd := awss3assets.NewAsset(stack, jsii.String("AWSNitroEnclaveMgmtService"), &awss3assets.AssetProps{
		Path: jsii.String(repoPath("enclave/systemd/enclave-mgmt.service")),
	})

	// Create SSM parameters for each configured secret.
	var secretParams []awsssm.StringParameter
	for _, secret := range secrets {
		param := awsssm.NewStringParameter(stack, jsii.String("Secret_"+secret.Name), &awsssm.StringParameterProps{
			StringValue:   jsii.String("UNSET"),
			ParameterName: jsii.String(fmt.Sprintf("/%s/%s/%s/Ciphertext", deployment, appName, secret.Name)),
		})
		secretParams = append(secretParams, param)

		// Migration ciphertext per secret.
		migParam := awsssm.NewStringParameter(stack, jsii.String("Migration_"+secret.Name), &awsssm.StringParameterProps{
			StringValue:   jsii.String("UNSET"),
			ParameterName: jsii.String(fmt.Sprintf("/%s/%s/Migration/%s/Ciphertext", deployment, appName, secret.Name)),
		})
		secretParams = append(secretParams, migParam)
	}

	// Shared migration parameters (one per deployment, not per secret).
	migrationKMSKeyIDParam := awsssm.NewStringParameter(stack, jsii.String("MigrationKMSKeyID"), &awsssm.StringParameterProps{
		StringValue:   jsii.String("UNSET"),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/MigrationKMSKeyID", deployment, appName)),
	})

	migrationPreviousPCR0Param := awsssm.NewStringParameter(stack, jsii.String("MigrationPreviousPCR0"), &awsssm.StringParameterProps{
		StringValue:   jsii.String("UNSET"),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName)),
	})

	migrationPreviousPCR0AttestationParam := awsssm.NewStringParameter(stack, jsii.String("MigrationPreviousPCR0Attestation"), &awsssm.StringParameterProps{
		StringValue:   jsii.String("UNSET"),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName)),
		Tier:          awsssm.ParameterTier_ADVANCED,
	})

	migrationOldKMSKeyIDParam := awsssm.NewStringParameter(stack, jsii.String("MigrationOldKMSKeyID"), &awsssm.StringParameterProps{
		StringValue:   jsii.String("UNSET"),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName)),
	})

	vpc := awsec2.NewVpc(stack, jsii.String("VPC"), &awsec2.VpcProps{
		NatGateways: jsii.Number(1),
		SubnetConfiguration: &[]*awsec2.SubnetConfiguration{
			{
				Name:       jsii.String("public"),
				SubnetType: awsec2.SubnetType_PUBLIC,
			},
			{
				Name:       jsii.String("private"),
				SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS,
			},
		},
		EnableDnsSupport:   jsii.Bool(true),
		EnableDnsHostnames: jsii.Bool(true),
	})

	awsec2.NewInterfaceVpcEndpoint(stack, jsii.String("KMSEndpoint"), &awsec2.InterfaceVpcEndpointProps{
		Vpc: vpc,
		Subnets: &awsec2.SubnetSelection{
			SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS,
		},
		Service:           awsec2.InterfaceVpcEndpointAwsService_KMS(),
		PrivateDnsEnabled: jsii.Bool(true),
	})

	awsec2.NewInterfaceVpcEndpoint(stack, jsii.String("SSMEndpoint"), &awsec2.InterfaceVpcEndpointProps{
		Vpc: vpc,
		Subnets: &awsec2.SubnetSelection{
			SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS,
		},
		Service:           awsec2.InterfaceVpcEndpointAwsService_SSM(),
		PrivateDnsEnabled: jsii.Bool(true),
	})

	awsec2.NewInterfaceVpcEndpoint(stack, jsii.String("ECREndpoint"), &awsec2.InterfaceVpcEndpointProps{
		Vpc: vpc,
		Subnets: &awsec2.SubnetSelection{
			SubnetType: awsec2.SubnetType_PRIVATE_WITH_EGRESS,
		},
		Service:           awsec2.InterfaceVpcEndpointAwsService_ECR(),
		PrivateDnsEnabled: jsii.Bool(true),
	})

	awsec2.NewGatewayVpcEndpoint(stack, jsii.String("S3Endpoint"), &awsec2.GatewayVpcEndpointProps{
		Vpc:     vpc,
		Service: awsec2.GatewayVpcEndpointAwsService_S3(),
	})

	nitroInstanceSG := awsec2.NewSecurityGroup(stack, jsii.String("NitroInstanceSG"), &awsec2.SecurityGroupProps{
		Vpc:              vpc,
		AllowAllOutbound: jsii.Bool(true),
		Description:      jsii.String("Private SG for Nitro Enclave EC2 instance"),
	})

	nitroInstanceSG.AddIngressRule(
		awsec2.Peer_AnyIpv4(),
		awsec2.Port_Tcp(jsii.Number(443)),
		jsii.String("Allow HTTPS from internet"),
		jsii.Bool(false),
	)

	// Use CfnSecurityGroupIngress for self-referencing rules to avoid
	// CloudFormation circular dependency with the EC2 instance.
	awsec2.NewCfnSecurityGroupIngress(stack, jsii.String("SelfTCP443"), &awsec2.CfnSecurityGroupIngressProps{
		GroupId:               nitroInstanceSG.SecurityGroupId(),
		SourceSecurityGroupId: nitroInstanceSG.SecurityGroupId(),
		IpProtocol:            jsii.String("tcp"),
		FromPort:              jsii.Number(443),
		ToPort:                jsii.Number(443),
	})

	awsec2.NewCfnSecurityGroupIngress(stack, jsii.String("SelfICMP"), &awsec2.CfnSecurityGroupIngressProps{
		GroupId:               nitroInstanceSG.SecurityGroupId(),
		SourceSecurityGroupId: nitroInstanceSG.SecurityGroupId(),
		IpProtocol:            jsii.String("icmp"),
		FromPort:              jsii.Number(-1),
		ToPort:                jsii.Number(-1),
	})

	amznLinux := awsec2.MachineImage_LatestAmazonLinux2023(nil)

	role := awsiam.NewRole(stack, jsii.String("InstanceSSM"), &awsiam.RoleProps{
		AssumedBy: awsiam.NewServicePrincipal(jsii.String("ec2.amazonaws.com"), nil),
	})
	role.AddManagedPolicy(
		awsiam.ManagedPolicy_FromAwsManagedPolicyName(jsii.String("AmazonSSMManagedInstanceCore")),
	)

	enclaveInit.GrantRead(role)
	enclaveInitSystemd.GrantRead(role)
	imdsSystemd.GrantRead(role)
	gvproxySystemd.GrantRead(role)
	mgmtBinary.GrantRead(role)
	mgmtSystemd.GrantRead(role)
	// Grant access to all per-secret SSM parameters (ciphertext + migration).
	for _, param := range secretParams {
		param.GrantRead(role)
		param.GrantWrite(role)
	}
	migrationKMSKeyIDParam.GrantRead(role)
	migrationPreviousPCR0Param.GrantRead(role)
	migrationPreviousPCR0Param.GrantWrite(role)
	migrationPreviousPCR0AttestationParam.GrantRead(role)
	migrationPreviousPCR0AttestationParam.GrantWrite(role)
	migrationOldKMSKeyIDParam.GrantRead(role)
	migrationOldKMSKeyIDParam.GrantWrite(role)

	blockDevice := awsec2.BlockDevice{
		DeviceName: jsii.String("/dev/xvda"),
		Volume: awsec2.BlockDeviceVolume_Ebs(jsii.Number(32), &awsec2.EbsDeviceOptions{
			VolumeType:          awsec2.EbsDeviceVolumeType_GP2,
			Encrypted:           jsii.Bool(true),
			DeleteOnTermination: jsii.Bool(deployment == "dev"),
		}),
	}

	mappings := map[string]*string{
		"__DEV_MODE__":                    jsii.String(deployment),
		"__APP_NAME__":                    jsii.String(appName),
		"__GVPROXY_IMAGE_URI__":           outboundProxyImage.ImageUri(),
		"__EIF_S3_URL__":                  enclaveEif.S3ObjectUrl(),
		"__ENCLAVE_INIT_S3_URL__":         enclaveInit.S3ObjectUrl(),
		"__ENCLAVE_INIT_SYSTEMD_S3_URL__": enclaveInitSystemd.S3ObjectUrl(),
		"__IMDS_SYSTEMD_S3_URL__":         imdsSystemd.S3ObjectUrl(),
		"__GVPROXY_SYSTEMD_S3_URL__":      gvproxySystemd.S3ObjectUrl(),
		"__MGMT_BINARY_S3_URL__":          mgmtBinary.S3ObjectUrl(),
		"__MGMT_SYSTEMD_S3_URL__":         mgmtSystemd.S3ObjectUrl(),
		"__REGION__":                      stack.Region(),
		"__KMS_KEY_ID__":                  encryptionKey.KeyId(),
	}

	userDataRaw := awscdk.Fn_Sub(jsii.String(ReadFileOrPanic(repoPath("enclave/user_data/user_data"))), &mappings)

	enclaveEif.GrantRead(role)
	outboundProxyImage.Repository().GrantPull(role)
	encryptionKey.GrantEncryptDecrypt(role)
	// The enclave self-applies KMS policy using its hardware-attested PCR0.
	// EC2 role needs PutKeyPolicy + GetKeyPolicy for this self-apply step.
	// These are granted both via IAM (Grant) and directly in the key policy
	// (AddToResourcePolicy) so the enclave can detect "PutKeyPolicy" in the
	// key policy string during selfApplyKMSPolicy().
	encryptionKey.Grant(role,
		jsii.String("kms:PutKeyPolicy"),
		jsii.String("kms:GetKeyPolicy"),
	)
	encryptionKey.AddToResourcePolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions:    jsii.Strings("kms:PutKeyPolicy", "kms:GetKeyPolicy"),
		Resources:  jsii.Strings("*"),
		Principals: &[]awsiam.IPrincipal{role},
	}), jsii.Bool(true))

	instance := awsec2.NewInstance(stack, jsii.String("NitroInstance"), &awsec2.InstanceProps{
		InstanceType: awsec2.NewInstanceType(jsii.String(instanceType)),
		Vpc:          vpc,
		VpcSubnets: &awsec2.SubnetSelection{
			SubnetType: awsec2.SubnetType_PUBLIC,
		},
		MachineImage:  amznLinux,
		BlockDevices:  &[]*awsec2.BlockDevice{&blockDevice},
		Role:          role,
		SecurityGroup: nitroInstanceSG,
		UserData:      awsec2.UserData_Custom(userDataRaw),
	})

	// Enable Nitro Enclaves on the underlying CFN resource (L2 InstanceProps has no NitroEnclaveEnabled field).
	cfnInstance := instance.Node().DefaultChild().(awsec2.CfnInstance)
	cfnInstance.AddPropertyOverride(jsii.String("EnclaveOptions.Enabled"), jsii.Bool(true))

	// Elastic IP gives the instance a static public address that survives reboots.
	eip := awsec2.NewCfnEIP(stack, jsii.String("EnclaveEIP"), &awsec2.CfnEIPProps{
		Domain: jsii.String("vpc"),
	})
	awsec2.NewCfnEIPAssociation(stack, jsii.String("EnclaveEIPAssoc"), &awsec2.CfnEIPAssociationProps{
		AllocationId: eip.AttrAllocationId(),
		InstanceId:   instance.InstanceId(),
	})

	kmsKeyIDParam := awsssm.NewStringParameter(stack, jsii.String("KMSKeyID"), &awsssm.StringParameterProps{
		StringValue:   encryptionKey.KeyId(),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)),
	})
	kmsKeyIDParam.GrantRead(role)

	// Encrypted persistent storage bucket for enclave data (Store/Load API).
	storageBucket := awss3.NewBucket(stack, jsii.String("EnclaveStorage"), &awss3.BucketProps{
		RemovalPolicy:     awscdk.RemovalPolicy_RETAIN,
		BlockPublicAccess: awss3.BlockPublicAccess_BLOCK_ALL(),
		EnforceSSL:        jsii.Bool(true),
	})
	storageBucket.GrantReadWrite(role, nil)

	storageBucketParam := awsssm.NewStringParameter(stack, jsii.String("StorageBucketName"), &awsssm.StringParameterProps{
		StringValue:   storageBucket.BucketName(),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/StorageBucketName", deployment, appName)),
	})
	storageBucketParam.GrantRead(role)

	// SSM parameter for the storage data encryption key (DEK).
	storageDEKParam := awsssm.NewStringParameter(stack, jsii.String("StorageDEK"), &awsssm.StringParameterProps{
		StringValue:   jsii.String("UNSET"),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/StorageDEK/Ciphertext", deployment, appName)),
	})
	storageDEKParam.GrantRead(role)
	storageDEKParam.GrantWrite(role)

	storageDEKMigrationParam := awsssm.NewStringParameter(stack, jsii.String("MigrationStorageDEK"), &awsssm.StringParameterProps{
		StringValue:   jsii.String("UNSET"),
		ParameterName: jsii.String(fmt.Sprintf("/%s/%s/Migration/StorageDEK/Ciphertext", deployment, appName)),
	})
	storageDEKMigrationParam.GrantRead(role)
	storageDEKMigrationParam.GrantWrite(role)

	awscdk.NewCfnOutput(stack, jsii.String("EC2 Instance Role ARN"), &awscdk.CfnOutputProps{
		Value:       role.RoleArn(),
		Description: jsii.String("EC2 Instance Role ARN"),
	})

	awscdk.NewCfnOutput(stack, jsii.String("KMS Key ID"), &awscdk.CfnOutputProps{
		Value:       encryptionKey.KeyId(),
		Description: jsii.String("KMS Key ID"),
	})

	awscdk.NewCfnOutput(stack, jsii.String("Instance ID"), &awscdk.CfnOutputProps{
		Value:       instance.InstanceId(),
		Description: jsii.String("EC2 Instance ID"),
	})

	awscdk.NewCfnOutput(stack, jsii.String("Elastic IP"), &awscdk.CfnOutputProps{
		Value:       eip.Ref(),
		Description: jsii.String("Static public IP for the enclave instance"),
	})

	return stack
}

// ReadFileOrPanic reads a file or exits the process.
func ReadFileOrPanic(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", path, err)
		os.Exit(1)
	}
	return string(data)
}
