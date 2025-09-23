# Oracle Cloud Free Tier Honeypot Deployment
terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

# Variables
variable "tenancy_ocid" {
  description = "OCID of your tenancy"
}

variable "user_ocid" {
  description = "OCID of the user"
}

variable "private_key_path" {
  description = "Path to your private key"
}

variable "fingerprint" {
  description = "Fingerprint of your public key"
}

variable "region" {
  description = "Oracle Cloud region"
  default = "us-ashburn-1"
}

# Provider configuration
provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  private_key_path = var.private_key_path
  fingerprint      = var.fingerprint
  region           = var.region
}

# Get availability domain
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

# Create VCN for isolation
resource "oci_core_vcn" "honeypot_vcn" {
  compartment_id = var.tenancy_ocid
  display_name   = "honeypot-vcn"
  cidr_block     = "10.1.0.0/16"
}

# Internet Gateway
resource "oci_core_internet_gateway" "honeypot_ig" {
  compartment_id = var.tenancy_ocid
  display_name   = "honeypot-ig"
  vcn_id         = oci_core_vcn.honeypot_vcn.id
}

# Route Table
resource "oci_core_route_table" "honeypot_rt" {
  compartment_id = var.tenancy_ocid
  vcn_id         = oci_core_vcn.honeypot_vcn.id
  display_name   = "honeypot-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.honeypot_ig.id
  }
}

# Security List (Firewall Rules)
resource "oci_core_security_list" "honeypot_sl" {
  compartment_id = var.tenancy_ocid
  vcn_id         = oci_core_vcn.honeypot_vcn.id
  display_name   = "honeypot-sl"

  # Allow all outbound
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }

  # SSH for management
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
  }

  # Honeypot services
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 80
      max = 80
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 443
      max = 443
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 21
      max = 21
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 23
      max = 23
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 3306
      max = 3306
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 5003
      max = 5003
    }
  }
}

# Subnet
resource "oci_core_subnet" "honeypot_subnet" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  cidr_block          = "10.1.20.0/24"
  display_name        = "honeypot-subnet"
  compartment_id      = var.tenancy_ocid
  vcn_id              = oci_core_vcn.honeypot_vcn.id
  route_table_id      = oci_core_route_table.honeypot_rt.id
  security_list_ids   = [oci_core_security_list.honeypot_sl.id]
}

# Get Ubuntu image
data "oci_core_images" "ubuntu_images" {
  compartment_id           = var.tenancy_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order              = "DESC"
}

# Honeypot Instance (Free Tier ARM)
resource "oci_core_instance" "honeypot_instance" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.tenancy_ocid
  display_name        = "isolated-honeypot"
  shape               = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = 4
    memory_in_gbs = 24
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.honeypot_subnet.id
    display_name     = "honeypot-vnic"
    assign_public_ip = true
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu_images.images[0].id
  }

  metadata = {
    ssh_authorized_keys = file("~/.ssh/id_rsa.pub")
    user_data          = base64encode(file("cloud-init.yaml"))
  }
}

# Output public IP
output "honeypot_public_ip" {
  value = oci_core_instance.honeypot_instance.public_ip
}

output "ssh_command" {
  value = "ssh ubuntu@${oci_core_instance.honeypot_instance.public_ip}"
}