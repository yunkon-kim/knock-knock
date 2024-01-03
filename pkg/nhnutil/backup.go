package nhnutil

// // UpdateSecurityGroup function updates a security group.
// func UpdateSecurityGroup(region Region, securityGroupId string, securityGroup SecurityGroup) (string, error) {

// 	client := resty.New()

// 	// Set API endpoint
// 	apiEndpoint := fmt.Sprintf(apiEndpointInfrastructureDocstring, region, Network)
// 	// Set API URL for a security group
// 	urlSecurityGroup := fmt.Sprintf("%s/v2.0/security-groups/%s", apiEndpoint, securityGroupId)

// 	// Set request body
// 	reqJsonBytes, err := json.Marshal(securityGroup)
// 	log.Debug().Msgf("Request Body: %s", reqJsonBytes)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to marshal JSON")
// 		return "", err
// 	}

// 	// Set Resty
// 	resp, err := client.R().
// 		SetHeader("X-Auth-Token", tokenId).
// 		SetHeader("Content-Type", "application/json").
// 		SetBody(reqJsonBytes).
// 		Put(urlSecurityGroup)

// 	if err != nil {
// 		log.Error().Err(err).Msg("Failed to update security group")
// 		return "", err
// 	}

// 	// Print result
// 	log.Info().Msg("Successfully updated security group")
// 	log.Debug().Msgf("Response Status Code: %d", resp.StatusCode())
// 	log.Debug().Msgf("Response Body: %s", resp.String())

// 	if resp.StatusCode() < http.StatusOK || resp.StatusCode() >= http.StatusMultipleChoices {
// 		// 2xx status codes indicate success, no error
// 		log.Error().Err(errors.New(resp.String())).Msg("Failed to update security group")
// 		return "", errors.New(resp.String())
// 	}

// 	return resp.String(), nil
// }

// // UpdateSecurityGroupRule function adds a security group rule.
// func UpdateSecurityGroupRule(securityGroup SecurityGroup, securityGroupRule SecurityGroupRuleDetails) (SecurityGroup, error) {

// 	sg := &securityGroup.SecurityGroup

// 	// Find and update the rule if it exists
// 	for i, rule := range sg.SecurityGroupRules {
// 		if rule.Id == securityGroupRule.Id {
// 			// if securityGroupRule.Direction != "" {
// 			// 	sg.SecurityGroupRules[i].Direction = securityGroupRule.Direction
// 			// }
// 			// if securityGroupRule.Protocol != "" {
// 			// 	sg.SecurityGroupRules[i].Protocol = securityGroupRule.Protocol
// 			// }
// 			if securityGroupRule.Description != "" {
// 				sg.SecurityGroupRules[i].Description = securityGroupRule.Description
// 			}
// 			// if securityGroupRule.PortRangeMax != 0 {
// 			// 	sg.SecurityGroupRules[i].PortRangeMax = securityGroupRule.PortRangeMax
// 			// }
// 			// if securityGroupRule.RemoteGroupId != "" {
// 			// 	sg.SecurityGroupRules[i].RemoteGroupId = securityGroupRule.RemoteGroupId
// 			// }
// 			if securityGroupRule.RemoteIpPrefix != "" {
// 				sg.SecurityGroupRules[i].RemoteIpPrefix = securityGroupRule.RemoteIpPrefix
// 			}
// 			// if securityGroupRule.SecurityGroupId != "" {
// 			// 	sg.SecurityGroupRules[i].SecurityGroupId = securityGroupRule.SecurityGroupId
// 			// }
// 			// if securityGroupRule.TenantId != "" {
// 			// 	sg.SecurityGroupRules[i].TenantId = securityGroupRule.TenantId
// 			// }
// 			// if securityGroupRule.PortRangeMin != 0 {
// 			// 	sg.SecurityGroupRules[i].PortRangeMin = securityGroupRule.PortRangeMin
// 			// }
// 			// if securityGroupRule.Ethertype != "" {
// 			// 	sg.SecurityGroupRules[i].Ethertype = securityGroupRule.Ethertype
// 			// }
// 			return securityGroup, nil
// 		}
// 	}

// 	// Append if the rule does not exist
// 	sg.SecurityGroupRules = append(sg.SecurityGroupRules, securityGroupRule)
// 	return securityGroup, nil
// }

// // GenSecurityGroup function creates an NHN Cloud security group.
// func GenSecurityGroup(securityGroupName string) {
// 	tfConfig := fmt.Sprintf(`
// resource "nhncloud_security_group" "%s" {
// 	name        = "%s"
// 	description = "Security group for %s"
// 	// Add necessary security rules here.
// }
// `, securityGroupName, securityGroupName, securityGroupName)

// 	createTerraformFile(filenameSecurityGroup, tfConfig)
// }

// // UpdateSecurityGroup 함수는 securityGroup 파일을 업데이트합니다.
// func UpdateSecurityGroup(securityGroupName, newRule string) error {
// 	filePath := filenameSecurityGroup
// 	updatedContent, err := addNewRuleToSecurityGroup(filePath, securityGroupName, newRule)
// 	if err != nil {
// 		return err
// 	}

// 	return overwriteFile(filePath, updatedContent)
// }

// // addNewRuleToSecurityGroup 함수는 보안 그룹에 새로운 규칙을 추가합니다.
// func addNewRuleToSecurityGroup(filePath, securityGroupName, newRule string) (string, error) {
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer file.Close()

// 	var updatedLines []string
// 	scanner := bufio.NewScanner(file)
// 	insideBlock := false

// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		if strings.Contains(line, fmt.Sprintf(`resource "nhncloud_security_group" "%s" {`, securityGroupName)) {
// 			insideBlock = true
// 		}

// 		if insideBlock && strings.Contains(line, "}") {
// 			updatedLines = append(updatedLines, newRule) // 새로운 규칙 추가
// 			insideBlock = false
// 		}

// 		updatedLines = append(updatedLines, line)
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return "", err
// 	}

// 	return strings.Join(updatedLines, "\n"), nil
// }

// // overwriteFile 함수는 파일의 내용을 덮어씁니다.
// func overwriteFile(filePath, content string) error {
// 	return os.WriteFile(filePath, []byte(content), 0644)
// }

// // AttachSecurityGroup function attaches a security group to a specific resource.
// func AttachSecurityGroup(resourceType, resourceName, securityGroupName string) {
// 	tfConfig := fmt.Sprintf(`
// resource "%s" "%s" {
// 	// Add resource details here.

// 	security_group = nhncloud_security_group.%s.id
// }
// `, resourceType, resourceName, securityGroupName)

// 	createTerraformFile(filenameAttachSecurityGroup, tfConfig)
// }

// // createTerraformFile function creates a Terraform file with the given content.
// func createTerraformFile(fileName, content string) {
// 	file, err := os.Create(fileName)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer file.Close()

// 	_, err = file.WriteString(content)
// 	if err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("Terraform configuration file '%s' created.\n", fileName)
// }

// // TerraformApply function applies the Terraform configuration.
// func TerraformApply() {
// 	cmd := exec.Command("terraform", "apply", "-auto-approve")
// 	cmd.Stdout = os.Stdout
// 	cmd.Stderr = os.Stderr
// 	if err := cmd.Run(); err != nil {
// 		panic(err)
// 	}
// }
