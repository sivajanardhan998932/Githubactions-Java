
package docker.security

import rego.v1

# Docker image must expose port 8080
deny contains "Docker image must expose port 8080" if {
    not input.exposed_ports["8080/tcp"]
}

# Docker image must have a startup command
deny contains "Docker image must have a startup command" if {
    count(input.cmd) == 0
}

# Docker image must not use the latest tag
deny contains "Docker image must not use latest tag" if {
    input.tag == "latest"
}

# Allow only when no policy violations exist
allow if {
    count(deny) == 0
}
