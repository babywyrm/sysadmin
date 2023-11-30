variable "ingress_rules" {
  type        = list(map(string))
  description = "VPC Default Security Group Ingress Rules"
  default = [
    {
      cidr_blocks = "0.0.0.0/0"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "Karpenter ingress allow"
    },
    { #other  CIDR blocks to which you might want to restrict access to (for example if this was your dev cluster)
      cidr_blocks = "XX.XX.XX.XXX/XX"
      from_port   = 0
      to_port     = 0
      protocol    = -1
      description = "MyCLuster-NAT"
    }
  ]
}
