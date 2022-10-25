package main

import (
	"fmt"
	"reflect"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

//A list of private subnets inside the VPC
var private_subnets []string = []string{}

//A list of nginx subnets inside the VPC
var nginx_subnets []string = []string{}

//A list of elasticache subnets
var elasticache_subnets []string = []string{}

//A list of database subnets
var database_subnets []string = []string{}

//A list of redshift_subnets
var redshift_subnets []string = []string{}

//A list of availability zones names or ids in the region
var azs []string = []string{}

var nat_gateway_count int

var computeName pulumi.StringOutput

var aws_vpc []*ec2.Vpc = []*ec2.Vpc{}

var vpcIpv4CidrBlockAssociation []*ec2.VpcIpv4CidrBlockAssociation = []*ec2.VpcIpv4CidrBlockAssociation{}

var defaultSecurityGroup *ec2.DefaultSecurityGroup

var internetGateway *ec2.InternetGateway

var egressOnlyInternetGateway *ec2.EgressOnlyInternetGateway

var awsDefaultRouteTable *ec2.DefaultRouteTable

var private_aws_route_table []*ec2.RouteTable

var public_internet_gateway, public_internet_gateway_ipv6 *ec2.Route

var awsVpcDhcpOptionsAssociation *ec2.VpcDhcpOptionsAssociation

type ProjectLevelConfig struct {
	Region                           string
	EncryptionKmsKey                 string
	IssueEmail                       string
	PrivateSubnets                   []string
	PublicSubnets                    []string
	NginxSubnets                     []string
	ElasticCacheSubnets              []string
	DatabaseSubnets                  []string
	RedshiftSubnets                  []string
	Azs                              []string
	SecondaryCidrBlocks              []string
	DefaultRouteTablePropagatingVgws []string
	DhcpOptionsDomainNameServers     []string
	DhcpOptionsNtpServers            []string
	DhcpOptionsNetbiosNameServers    []string
	DhcpOptionsNetbiosNodeType       string
	DefaultSecurityGroupIngress      []map[string]interface{}
	DefaultSecurityGroupEgress       []map[string]interface{}
	DefaultRouteTableRoutes          []map[string]interface{}
	Tags                             map[string]string
	DefaultSecurityGroupTags         map[string]string
	DhcpOptionsTags                  map[string]string
	IgwTags                          map[string]string
	PrivateRouteTableTags            map[string]string
	SingleNatGateway                 bool
	OneNatGatewayPerAz               bool
	DhcpOptionsDomainName            string
	AwsProfile                       string
	Name                             string
	Cidr                             string
	InstanceTenancy                  string
	DefaultSecurityGroupName         string
	PrivateSubnetSuffix              string
	EnableDnsHostNames               bool
	EnableDnsSupport                 bool
	EnableClassicLink                bool
	EnableDhcpOptions                bool
	EnableClassicLinkDnsSupport      bool
	EnableIpv6                       bool
	CreateVpc                        bool
	ManageDefaultSecurityGroup       bool
	ManageDefaultRouteTable          bool
	CreateIgw                        bool
	CreateEgressOnlyIgw              bool
}

func Max(input []int) int {
	aux := 0
	for _, v := range input {
		if aux <= v {
			aux = v
		}
	}
	return aux
}

//TODO should be fetched by Pulumi.<stack>.yaml
var projectLevelConfig = ProjectLevelConfig{
	Region:           "eu-central-1",
	EncryptionKmsKey: "",
	IssueEmail:       "",
	PrivateSubnets:   []string{},
	//A list of public subnets inside the VPC
	PublicSubnets:       []string{},
	NginxSubnets:        []string{},
	ElasticCacheSubnets: []string{},
	DatabaseSubnets:     []string{},
	RedshiftSubnets:     []string{},
	Azs:                 []string{},
	SecondaryCidrBlocks: []string{"10.2.0.0/16", "10.3.0.0/16"},
	//List of virtual gateways for propagation
	DefaultRouteTablePropagatingVgws: []string{},
	DhcpOptionsDomainNameServers:     []string{"AmazonProvidedDNS"},
	DhcpOptionsNtpServers:            []string{},
	DhcpOptionsNetbiosNameServers:    []string{},
	DhcpOptionsNetbiosNodeType:       "",
	DefaultSecurityGroupIngress:      []map[string]interface{}{{"CidrBlocks": []string{"10.0.0.0/16"}, "FromPort": 80, "Description": "Allow ingress on port 80"}},
	DefaultSecurityGroupEgress:       []map[string]interface{}{{"CidrBlocks": []string{"10.0.0.0/16"}, "FromPort": 80, "Description": "Allow ingress on port 80"}},
	//Configuration block of routes. See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_route_table#route
	DefaultRouteTableRoutes:  []map[string]interface{}{},
	Tags:                     map[string]string{},
	DefaultSecurityGroupTags: map[string]string{},
	DhcpOptionsTags:          map[string]string{},
	//Additional tags for the private route tables
	PrivateRouteTableTags: map[string]string{},
	//Additional tags for the internet gateway
	IgwTags:                     map[string]string{},
	SingleNatGateway:            false,
	OneNatGatewayPerAz:          false,
	AwsProfile:                  "vodafone-dms",
	Name:                        "aws-vpc",
	Cidr:                        "10.0.0.0/16",
	InstanceTenancy:             "default",
	DefaultSecurityGroupName:    "default-aws-security-group",
	DhcpOptionsDomainName:       "aws-dhcp-domain",
	PrivateSubnetSuffix:         "private",
	EnableDnsHostNames:          false,
	EnableDnsSupport:            true,
	EnableDhcpOptions:           true,
	EnableClassicLink:           true,
	EnableClassicLinkDnsSupport: true,
	EnableIpv6:                  false,
	CreateVpc:                   true,
	//Should be true to adopt and manage default security group
	ManageDefaultSecurityGroup: false,
	//Should be true to manage default route table
	ManageDefaultRouteTable: false,
	//Controls if an Internet Gateway is created for public subnets and the related routes that connect them.
	CreateIgw: true,
	//Controls if an Egress Only Internet Gateway is created and its related routes.
	CreateEgressOnlyIgw: true,
}

func assignStructValues(structInterface interface{}, values map[string]interface{}) {
	structType := reflect.TypeOf(structInterface).Elem()
	structValue := reflect.ValueOf(structInterface)

	for i := 0; i < structType.NumField(); i++ {
		fieldName := structType.Field(i).Name

		if val, ok := values[fieldName]; ok {
			newValue := reflect.ValueOf(val)
			structValue.Elem().Field(i).Set(newValue)
		}
	}
}

func main() {

	//Should be true if you want to provision a single shared NAT Gateway across all of your private networks
	single_nat_gateway := projectLevelConfig.SingleNatGateway

	//Should be true if you want only one NAT Gateway per availability zone. Requires `azs` to be set, and the number of `public_subnets` created to be greater than or equal to the number of availability zones specified in `var.azs`
	one_nat_gateway_per_az := projectLevelConfig.OneNatGatewayPerAz

	max_subnet_length := Max([]int{len(projectLevelConfig.PrivateSubnets), len(projectLevelConfig.NginxSubnets), len(projectLevelConfig.ElasticCacheSubnets), len(projectLevelConfig.DatabaseSubnets), len(projectLevelConfig.RedshiftSubnets)})

	switch single_nat_gateway {
	case true:
		nat_gateway_count = 1
	default:
		switch one_nat_gateway_per_az {
		case true:
			nat_gateway_count = len(projectLevelConfig.Azs)
		default:
			nat_gateway_count = max_subnet_length
		}
	}

	instance_tenancy := "default"
	// Should be true to enable DNS hostnames in the VPC
	enable_dns_hostnames := false
	//should be true to enable DNS support in the VPC
	enable_dns_support := true
	//Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for the VPC. You cannot specify the range of IP addresses, or the size of the CIDR block.
	enable_ipv6c := false

	pulumi.Run(func(ctx *pulumi.Context) error {
		//=========================================================================
		// Provider Configuration AWS
		//=========================================================================
		aws, err := aws.NewProvider(ctx, "vf-region", &aws.ProviderArgs{
			Region:  pulumi.String(projectLevelConfig.Region),
			Profile: pulumi.String(projectLevelConfig.AwsProfile),
		})
		if err != nil {
			return err
		}
		fmt.Println("Provider's Region:" + aws.Region.ElementType().String())

		//==========================================================================
		// VPC Provisioning
		//==========================================================================
		tags := make(map[string]pulumi.StringInput, 1)
		tags["Name"] = pulumi.StringInput(pulumi.String(projectLevelConfig.Name))
		if projectLevelConfig.CreateVpc {
			aws_vpc_res, err := ec2.NewVpc(ctx, fmt.Sprintf("dms-%s", projectLevelConfig.Name), &ec2.VpcArgs{
				CidrBlock:                    pulumi.String(projectLevelConfig.Cidr),
				InstanceTenancy:              pulumi.String(instance_tenancy),
				EnableDnsHostnames:           pulumi.Bool(enable_dns_hostnames),
				EnableDnsSupport:             pulumi.Bool(enable_dns_support),
				AssignGeneratedIpv6CidrBlock: pulumi.Bool(enable_ipv6c),
				Tags:                         pulumi.StringMap(tags),
			})
			if err != nil {
				return err
			}
			aws_vpc = append(aws_vpc, aws_vpc_res)
		}

		//===========================================================================
		//VPC IPV4 CIDR BLOCK Provisioning
		//===========================================================================

		for i := 0; i < len(projectLevelConfig.SecondaryCidrBlocks); i++ {
			aws_vpc_cidr_blocks, err := ec2.NewVpcIpv4CidrBlockAssociation(ctx, fmt.Sprintf("vpcIpv4CidrBlockAssociation-%v", i), &ec2.VpcIpv4CidrBlockAssociationArgs{
				VpcId:     aws_vpc[0].ID().ToStringOutput(),
				CidrBlock: pulumi.String(projectLevelConfig.SecondaryCidrBlocks[i]),
			})
			if err != nil {
				return err
			}
			vpcIpv4CidrBlockAssociation = append(vpcIpv4CidrBlockAssociation, aws_vpc_cidr_blocks)
		}

		//============================================================================
		//Default Security Group
		//============================================================================
		if projectLevelConfig.CreateVpc && projectLevelConfig.ManageDefaultSecurityGroup {

			//========================================================================
			// Default Security Group Args dynamic association
			//========================================================================

			security_groups_ingress := ec2.DefaultSecurityGroupIngressArray{}
			security_groups_egress := ec2.DefaultSecurityGroupEgressArray{}

			for i := 0; i < len(projectLevelConfig.DefaultSecurityGroupIngress); i++ {
				group_ingress := &ec2.DefaultSecurityGroupIngressArgs{}
				assignStructValues(group_ingress, projectLevelConfig.DefaultSecurityGroupIngress[i])
				security_groups_ingress = append(security_groups_ingress, group_ingress)

			}

			for i := 0; i < len(projectLevelConfig.DefaultSecurityGroupEgress); i++ {
				group_egress := &ec2.DefaultSecurityGroupEgressArgs{}
				assignStructValues(group_egress, projectLevelConfig.DefaultSecurityGroupEgress[i])
				security_groups_egress = append(security_groups_egress, group_egress)

			}

			//merge tags
			tags := make(map[string]pulumi.StringInput, 1)
			tags["Name"] = pulumi.StringInput(pulumi.String(projectLevelConfig.DefaultSecurityGroupName))
			for k, v := range projectLevelConfig.Tags {
				tags[projectLevelConfig.Tags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.Tags[v]))
			}
			for k, v := range projectLevelConfig.DefaultSecurityGroupTags {
				tags[projectLevelConfig.DefaultSecurityGroupTags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.DefaultSecurityGroupTags[v]))
			}
			//merge tags ends

			defaultSecurityGroup, err = ec2.NewDefaultSecurityGroup(ctx, fmt.Sprintf("defaultSecurityGroup"), &ec2.DefaultSecurityGroupArgs{
				VpcId:   aws_vpc[0].ID().ToStringOutput(),
				Ingress: security_groups_ingress,
				Egress:  security_groups_egress,
				Tags:    pulumi.StringMap(tags),
			})
			if err != nil {
				return err
			}
		}

		// //============================================================================
		// //DHCP Options Set
		// //============================================================================
		var vpc_id pulumi.StringOutput
		//interpolate vpc_id from pulumi.StringOutput
		if len(vpcIpv4CidrBlockAssociation) > 0 {
			vpc_id = pulumi.Sprintf("%s", vpcIpv4CidrBlockAssociation[0].VpcId)
		} else {
			vpc_id = pulumi.Sprintf("%s", aws_vpc[0].ID().ToStringOutput())
		}

		if projectLevelConfig.CreateVpc && projectLevelConfig.EnableDhcpOptions {

			//merge tags
			tags := make(map[string]pulumi.StringInput)
			tags["Name"] = pulumi.StringInput(pulumi.String(projectLevelConfig.Name))
			for k, v := range projectLevelConfig.Tags {
				tags[projectLevelConfig.Tags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.Tags[v]))
			}
			for k, v := range projectLevelConfig.DhcpOptionsTags {
				tags[projectLevelConfig.DhcpOptionsTags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.DhcpOptionsTags[v]))
			}
			//merge tags ends

			vpcDhcpOptions, err := ec2.NewVpcDhcpOptions(ctx, "aws_vpc_dhcp_options", &ec2.VpcDhcpOptionsArgs{
				DomainName:         pulumi.String(projectLevelConfig.DhcpOptionsDomainName),
				DomainNameServers:  pulumi.StringArrayInput(pulumi.ToStringArray(projectLevelConfig.DhcpOptionsDomainNameServers)),
				NtpServers:         pulumi.StringArrayInput(pulumi.ToStringArray(projectLevelConfig.DhcpOptionsNtpServers)),
				NetbiosNameServers: pulumi.StringArrayInput(pulumi.ToStringArray(projectLevelConfig.DhcpOptionsNetbiosNameServers)),
				NetbiosNodeType:    pulumi.String(projectLevelConfig.DhcpOptionsNetbiosNodeType),
				Tags:               pulumi.StringMap(tags),
			})
			if err != nil {
				return err
			}

			//============================================================================
			// DHCP Options set Association
			//============================================================================

			awsVpcDhcpOptionsAssociation, err = ec2.NewVpcDhcpOptionsAssociation(ctx, "aws_vpc_dhcp_options_association", &ec2.VpcDhcpOptionsAssociationArgs{
				VpcId:         pulumi.StringInput(vpc_id),
				DhcpOptionsId: vpcDhcpOptions.ID().ToStringOutput(),
			})
			if err != nil {
				return err
			}
		}

		// //================================================================================
		// // Internet Gateway
		// //================================================================================
		// //merge tags
		// tags := make(map[string]pulumi.StringInput)
		// tags["Name"] = pulumi.StringInput(pulumi.String(projectLevelConfig.Name))
		// for k, v := range projectLevelConfig.Tags {
		// 	tags[projectLevelConfig.Tags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.Tags[v]))
		// }
		// for k, v := range projectLevelConfig.IgwTags {
		// 	tags[projectLevelConfig.IgwTags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.IgwTags[v]))
		// }
		// //merge tags ends

		// if projectLevelConfig.CreateVpc && projectLevelConfig.CreateIgw && len(projectLevelConfig.PublicSubnets) > 0 {

		// 	internetGateway, err = ec2.NewInternetGateway(ctx, "aws_internet_gateway", &ec2.InternetGatewayArgs{
		// 		VpcId: pulumi.StringPtrInput(vpc_id),
		// 		Tags:  pulumi.StringMapInput(pulumi.StringMap(tags)),
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		// if projectLevelConfig.CreateVpc && projectLevelConfig.CreateEgressOnlyIgw && projectLevelConfig.EnableIpv6 && max_subnet_length > 0 {
		// 	egressOnlyInternetGateway, err = ec2.NewEgressOnlyInternetGateway(ctx, "aws_egress_only_internet_gateway", &ec2.EgressOnlyInternetGatewayArgs{
		// 		VpcId: pulumi.StringInput(vpc_id),
		// 		Tags:  pulumi.StringMapInput(pulumi.StringMap(tags)),
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		// //===============================================================================
		// // Default Route
		// //===============================================================================

		// route_table_routes := ec2.DefaultRouteTableRouteArray{}

		// if projectLevelConfig.CreateVpc && projectLevelConfig.ManageDefaultRouteTable {
		// 	for i := 0; i < len(projectLevelConfig.DefaultRouteTableRoutes); i++ {
		// 		default_route_item := &ec2.DefaultRouteTableRouteArgs{}
		// 		assignStructValues(default_route_item, projectLevelConfig.DefaultRouteTableRoutes[i])
		// 		route_table_routes = append(route_table_routes, default_route_item)
		// 	}

		// 	awsDefaultRouteTable, err = ec2.NewDefaultRouteTable(ctx, "aws_default_route_table", &ec2.DefaultRouteTableArgs{
		// 		DefaultRouteTableId: aws_vpc[0].DefaultRouteTableId,
		// 		PropagatingVgws:     pulumi.StringArrayInput(pulumi.ToStringArray(projectLevelConfig.DefaultRouteTablePropagatingVgws)),
		// 		Routes:              route_table_routes,
		// 		Tags:                nil,
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}
		// }
		// //==============================================================================
		// //Public Routes
		// //==============================================================================
		// if projectLevelConfig.CreateVpc && len(projectLevelConfig.PublicSubnets) > 0 {

		// 	awsRouteTable, err := ec2.NewRouteTable(ctx, "public", &ec2.RouteTableArgs{
		// 		VpcId: pulumi.StringInput(vpc_id),
		// 		Tags:  nil,
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}

		// 	public_internet_gateway, err = ec2.NewRoute(ctx, "public_internet_gateway", &ec2.RouteArgs{
		// 		RouteTableId:         pulumi.StringInput(awsRouteTable.ID().ToStringOutput()),
		// 		DestinationCidrBlock: pulumi.StringPtrInput(pulumi.String("0.0.0.0/0")),
		// 		GatewayId:            internetGateway.ID(),
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}

		// 	public_internet_gateway_ipv6, err = ec2.NewRoute(ctx, "public_internet_gateway_ipv6", &ec2.RouteArgs{
		// 		RouteTableId:             pulumi.StringInput(awsRouteTable.ID().ToStringOutput()),
		// 		DestinationIpv6CidrBlock: pulumi.StringPtrInput(pulumi.String("::/0")),
		// 		GatewayId:                internetGateway.ID(),
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		// //================================================================================
		// // Private Routes - There are as many routing tables as the number of NAT gateways
		// //================================================================================
		// count := 0
		// if projectLevelConfig.CreateVpc && max_subnet_length > 0 {
		// 	count = nat_gateway_count
		// }

		// //merge tags
		// tags = make(map[string]pulumi.StringInput)

		// for k, v := range projectLevelConfig.Tags {
		// 	tags[projectLevelConfig.Tags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.Tags[v]))
		// }
		// for k, v := range projectLevelConfig.IgwTags {
		// 	tags[projectLevelConfig.PrivateRouteTableTags[k]] = pulumi.StringInput(pulumi.String(projectLevelConfig.PrivateRouteTableTags[v]))
		// }
		// //merge tags ends

		// for i := 0; i < count; i++ {
		// 	if single_nat_gateway {
		// 		computeName = pulumi.Sprintf("%s-%s", projectLevelConfig.Name, projectLevelConfig.PrivateSubnetSuffix)
		// 	} else {
		// 		computeName = pulumi.Sprintf("%s-%s-%s", projectLevelConfig.Name, projectLevelConfig.PrivateSubnetSuffix, projectLevelConfig.Azs[count])
		// 	}
		// 	tags["Name"] = pulumi.StringInput(computeName)
		// 	awsPrivateRouteTable, err := ec2.NewRouteTable(ctx, "private", &ec2.RouteTableArgs{
		// 		VpcId: pulumi.StringInput(vpc_id),
		// 		Tags:  pulumi.StringMapInput(pulumi.StringMap(tags)),
		// 	})
		// 	if err != nil {
		// 		return err
		// 	}
		// 	private_aws_route_table = append(private_aws_route_table, awsPrivateRouteTable)
		// }

		// // opt0 := "default"
		// // vpc, err := ec2.NewVpc(ctx, name, &ec2.VpcArgs{
		// // 	CidrBlock:          pulumi.String(cidr),
		// // 	InstanceTenancy:    pulumi.String(instance_tenancy),
		// // 	EnableDnsHostnames: pulumi.Bool(enable_dns_hostnames),
		// // 	EnableDnsSupport:   pulumi.Bool(enable_dns_support),
		// // 	EnableClassiclink:  pulumi.Bool(enable_classiclink),
		// // })
		// // vpc_parent, vpc_err := NewVpc(ctx,"aws-vpc",ec2.NewVpc())
		// // if vpc_err != nil {
		// // 	return vpc_err
		// // }
		// // sg, err = ec2.LookupSecurityGroup(ctx, &ec2.LookupSecurityGroupArgs{
		// // 	Name:  &opt0,
		// // 	VpcId: &vpc.ComponentResource.URN(),
		// // }, nil)
		// // if err != nil {
		// // 	return err
		// // }
		// // opt2 := "available"
		// // _, err = aws.GetAvailabilityZones(ctx, &aws.GetAvailabilityZonesArgs{
		// // 	State: &opt2,
		// // }, nil)
		// // if err != nil {
		// // 	return err
		// // }
		// // _, err = random.NewRandomString(ctx, "suffix", &random.RandomStringArgs{
		// // 	Length:  pulumi.Int(8),
		// // 	Special: pulumi.Bool(false),
		// // })
		// // if err != nil {
		// // 	return err
		// // }
		return nil
	})
}
