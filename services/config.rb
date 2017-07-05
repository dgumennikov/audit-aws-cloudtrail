# user-visible engine-powered rule definitions


coreo_aws_rule "cloudtrail-service-disabled" do
  action :define
  service :cloudtrail
  link "http://kb.cloudcoreo.com/mydoc_cloudtrail-service-disabled.html"
  display_name "Cloudtrail Service is Disabled"
  description "CloudTrail logging is not enabled for this region. It should be enabled."
  category "Audit"
  suggested_action "Enable CloudTrail logs for each region."
  level "Low"
  meta_cis_id "2.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.1.12, 3.3.7, 3.3.2"
  meta_markiz "nursultan"
  meta_test "attribute"
  meta_nist_tag "test_nist_tag"
  objectives ["trails"]
  formulas ["count"]
  audit_objects ["trail_list"]
  operators ["=="]
  raise_when [0]
  id_map "stack.current_region"
end
