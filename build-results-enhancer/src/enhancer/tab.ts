import Controls = require("VSS/Controls");
import VSS_Service = require("VSS/Service");
import TFS_Build_Contracts = require("TFS/Build/Contracts");
import TFS_Build_Extension_Contracts = require("TFS/Build/ExtensionContracts");
import DT_Client = require("TFS/DistributedTask/TaskRestClient");

export class InfoTab extends Controls.BaseControl {	
	constructor() {
		super();
	}
		
	public initialize(): void {
		super.initialize();
		// Get configuration that's shared between extension and the extension host
		var sharedConfig: TFS_Build_Extension_Contracts.IBuildResultsViewExtensionConfig = VSS.getConfiguration();
		var vsoContext = VSS.getWebContext();
		if(sharedConfig) {
			// register your extension with host through callback
			sharedConfig.onBuildChanged((build: TFS_Build_Contracts.Build) => {
				this._initBuildInfo(build);	
				var taskClient = DT_Client.getClient();

				taskClient.getPlanAttachments(vsoContext.project.id, "build", build.orchestrationPlan.planId, "FortifyRiskReport").then((taskAttachments) => {
						if (taskAttachments.length === 1) {
						$(".risk-report-message").remove();
						var recId = taskAttachments[0].recordId;
						var timelineId = taskAttachments[0].timelineId;
						var link = taskAttachments[0]._links.self.href;
						var attachmentName = taskAttachments[0].name;

						//$(".risk-report").append(" : ");
						//$(".risk-report").append(attachmentName);
						//$(".risk-report").append(" : ");
						//$(".risk-report").append(link);
						//$(".risk-report").append(" : ");
						//$(".risk-report").append(timelineId);
						//$(".risk-report").append(" : ");
						//$(".risk-report").append(recId);

						taskClient.getAttachmentContent(vsoContext.project.id, "build", build.orchestrationPlan.planId, timelineId, recId, "FortifyRiskReport", attachmentName).then((attachementContent) => {
							function arrayBufferToString(buffer) {
								var arr = new Uint8Array(buffer);
								var str = String.fromCharCode.apply(String, arr);
								return str;
							}

							var summaryPageData = arrayBufferToString(attachementContent);
							var FortifyObject = JSON.parse(summaryPageData);
							$(".risk-report").append(FortifyObject);

							var bomCount = $("<div>", { "class": "total-count", "text": "SCA Vulnerabilities: " + FortifyObject.count });
							var bom = $("<table>", { "class": "bom" });
							var bomSummary = $("<table>", { "class": "bomSum" });
							$(".risk-report").append(bomCount);
							$(".risk-report").append(bomSummary);

							var CriticalVulnCount = 0;
							var highVulnCount = 0;
							var mediumVulnCount = 0;
							var lowVulnCount = 0;

							for (var i = 0; i < FortifyObject.count; i++) {
								if (FortifyObject.data[i].friority == "Critical") {
									CriticalVulnCount++;
								}
								if (FortifyObject.data[i].friority == "High") {
									highVulnCount++;
								}
								if (FortifyObject.data[i].friority == "Medium") {
									mediumVulnCount++;
								}
								if (FortifyObject.data[i].friority == "Low") {
									lowVulnCount++;
								}
							}

							$(".bomSum").append("<tr class='bomSum-header-row'><th class='policy-status-header'><th class='component-header'>Issues Type</th><th class='security-risk-header'>Count</th></tr>");

							$(".bomSum-header-row").after("<tr><td class='policy-status-icon'>" +
								"<span class='fa fa-ban in-violation'></span></td>" +
								"<td>Critical</td>" +
								"<td>" + CriticalVulnCount.toString() + "</td>" +
								"</tr>" + 
								"<tr><td class='policy-status-icon'><span class='fa fa-ban in-violation'></span></td>" +
								"<td>High</td>" +
								"<td>" + highVulnCount.toString() + "</td>" +
								"</tr>"	+							
								"<tr><td class='policy-status-icon'><span class='fa fa-exclamation-circle in-violation-overridden'></span></td>" +
								"<td>Medium</td>" +
								"<td>" + mediumVulnCount.toString() + "</td>" +
								"</tr>"	+							
								"<tr><td class='policy-status-icon'><span class='not-in-violation'></span></td>" +
								"<td>Low</td>" +
								"<td>" + lowVulnCount.toString() + "</td>" +
								"</tr>"								
								);
							$(".risk-report").append("<br>");
							$(".risk-report").append(bom);


							$(".bom").append("<tr class='bom-header-row'><th class='policy-status-header'><th class='component-header'>issueName</th><th>Component</th><th class='security-risk-header'>Security Risk</th></tr>");


							for (var i = 0; i < FortifyObject.count; i++) {
								var highVulnClass = "high-vuln-count";
								var mediumVulnClass = "medium-vuln-count";
								var lowVulnClass = "low-vuln-count";
								var policyClass = "fa fa-ban in-violation";

								if (FortifyObject.data[i].friority == "Critical") {
									$(".bom-header-row").after("<tr><td class='policy-status-icon'>" +
										"<span class='" + policyClass + "'></span></td>" +
										"<td><a href='" + FortifyObject.data[i]._href + "' target='_blank'>" +
										FortifyObject.data[i].issueName + " " + FortifyObject.data[i].analyzer + "</a>" +
										"</td><td>" + FortifyObject.data[i].primaryLocation +
										"</td><td>" +
										"<div class='risk-panel'>" +
										"<span class='" + highVulnClass + "'>" +
										FortifyObject.data[i].friority +
										"</span>" +
										"</div></td></tr>");
								}

								if (FortifyObject.data[i].friority == "High") {
									$(".bom-header-row").after("<tr><td class='policy-status-icon'>" +
										"<span class='" + policyClass + "'></span></td>" +
										"<td><a href='" + FortifyObject.data[i]._href + "' target='_blank'>" +
										FortifyObject.data[i].issueName + " " + FortifyObject.data[i].analyzer + "</a>" +
										"</td><td>" + FortifyObject.data[i].primaryLocation +
										"</td><td>" +
										"<div class='risk-panel'>" +
										"<span class='" + highVulnClass + "'>" +
										FortifyObject.data[i].friority +
										"</span>" +
										"</div></td></tr>");
								}
								if (FortifyObject.data[i].friority == "Medium") {
									$(".bom-header-row").after("<tr><td class='policy-status-icon'>" +
										"<span class='fa fa-exclamation-circle in-violation-overridden'></span></td>" +
										"<td><a href='" + FortifyObject.data[i]._href + "' target='_blank'>" +
										FortifyObject.data[i].issueName + " " + FortifyObject.data[i].analyzer + "</a>" +
										"</td><td>" + FortifyObject.data[i].primaryLocation +
										"</td><td>" +
										"<div class='risk-panel'>" +
										"<span class='" + mediumVulnClass + "'>" +
										FortifyObject.data[i].friority +
										"</span>" +
										"</div></td></tr>");
								}
								if (FortifyObject.data[i].friority == "Low") {
									$(".bom-header-row").after("<tr><td class='policy-status-icon'>" +
										"<span class='not-in-violation'></span></td>" +
										"<td><a href='" + FortifyObject.data[i]._href + "' target='_blank'>" +
										FortifyObject.data[i].issueName + " " + FortifyObject.data[i].analyzer + "</a>" +
										"</td><td>" + FortifyObject.data[i].primaryLocation +
										"</td><td>" +
										"<div class='risk-panel'>" +
										"<span class='" + lowVulnClass + "'>" +
										FortifyObject.data[i].friority +
										"</span>" +
										"</div></td></tr>");
								}
							}

							//var projectVersion = "<div class='project-version'><span>" +
							//	"<a href='" + summaryPageData.data.projectLink + "' target='_blank'>" + summaryPageData.projectName + "</a></span>" +
							//	"<span class='project-version-separator'><i class='fa fa-caret-right'></i></span><span>" +
							//	"<a href='" + summaryPageData.projectVersionLink + "' target='_blank'>" + summaryPageData.projectVersion + "</a></span></div>"

							//$(".risk-report").append(projectVersion);

							// do some thing here
							// see how to get auth https://www.visualstudio.com/en-us/docs/report/analytics/building-extension-against-analytics-service

						});
					}
				});
			});
		}		
	}
	
	private _initBuildInfo(build: TFS_Build_Contracts.Build) {
		
	}
}

InfoTab.enhance(InfoTab, $(".fortify-report"), {});

// Notify the parent frame that the host has been loaded
VSS.notifyLoadSucceeded();

	
