# frozen_string_literal: true

module RBAC
  # Evaluates organization entitlement data against RBAC/ABAC policy rules.
  # Generates policy violations used in compliance reports.
  class PolicyEngine
    POLICIES = [
      {
        id: 'POL-001',
        name: 'Stale Admin Access',
        description: 'Organization admins must show activity within 90 days',
        severity: :critical,
        framework_controls: { 'SOC2' => 'CC6.1', 'ISO27001' => 'A.9.2.5', 'HIPAA' => '164.312(a)(1)' }
      },
      {
        id: 'POL-002',
        name: 'Least Privilege — Admin Repo Access',
        description: 'Members should not have admin access to more than 5 repositories',
        severity: :high,
        framework_controls: { 'SOC2' => 'CC6.3', 'ISO27001' => 'A.9.4.1', 'HIPAA' => '164.312(a)(1)' }
      },
      {
        id: 'POL-003',
        name: 'Stale Member Access',
        description: 'Organization members must show activity within 90 days',
        severity: :medium,
        framework_controls: { 'SOC2' => 'CC6.2', 'ISO27001' => 'A.9.2.6', 'HIPAA' => '164.308(a)(3)' }
      },
      {
        id: 'POL-004',
        name: 'Outside Collaborator Review',
        description: 'Outside collaborators require quarterly access review',
        severity: :high,
        framework_controls: { 'SOC2' => 'CC6.6', 'ISO27001' => 'A.9.2.2', 'HIPAA' => '164.308(a)(3)' }
      },
      {
        id: 'POL-005',
        name: 'Excessive Team Membership',
        description: 'Members should not belong to more than 10 teams',
        severity: :low,
        framework_controls: { 'SOC2' => 'CC6.3', 'ISO27001' => 'A.9.4.1', 'HIPAA' => '164.312(a)(1)' }
      },
      {
        id: 'POL-006',
        name: 'Secret Team Governance',
        description: 'Secret teams must have fewer than 5 members',
        severity: :medium,
        framework_controls: { 'SOC2' => 'CC6.1', 'ISO27001' => 'A.9.1.2', 'HIPAA' => '164.312(a)(1)' }
      }
    ].freeze

    # Evaluate entitlement audit results against all policies
    # @param audit_results [Hash] from EntitlementAuditor#run
    # @return [Array<Hash>] list of policy violations
    def evaluate(audit_results)
      violations = []
      members = audit_results[:members] || []
      teams = audit_results[:teams] || []
      outside_collabs = audit_results[:outside_collaborators] || []

      members.each do |member|
        violations += check_pol001(member)
        violations += check_pol002(member)
        violations += check_pol003(member)
        violations += check_pol005(member)
      end

      outside_collabs.each do |collab|
        violations += check_pol004(collab)
      end

      teams.each do |team|
        violations += check_pol006(team)
      end

      violations
    end

    def policy_catalog
      POLICIES
    end

    def compliance_score(violations, total_checks)
      return 100 if total_checks.zero?

      passing = total_checks - violations.size
      ((passing.to_f / total_checks) * 100).round(1)
    end

    private

    def check_pol001(member)
      return [] unless member[:is_admin] && member[:stale]

      [build_violation('POL-001', member[:login], "Admin #{member[:login]} has been inactive for #{member[:days_since_active]} days")]
    end

    def check_pol002(member)
      admin_repos = member[:repos_with_admin] || 0
      return [] unless admin_repos > 5

      [build_violation('POL-002', member[:login], "#{member[:login]} has admin access to #{admin_repos} repositories (limit: 5)")]
    end

    def check_pol003(member)
      return [] unless !member[:is_admin] && member[:stale]

      [build_violation('POL-003', member[:login], "Member #{member[:login]} inactive for #{member[:days_since_active]} days")]
    end

    def check_pol004(collab)
      return [] unless collab[:stale]

      [build_violation('POL-004', collab[:login], "Outside collaborator #{collab[:login]} inactive for #{collab[:days_since_active]} days")]
    end

    def check_pol005(member)
      return [] unless (member[:team_count] || 0) > 10

      [build_violation('POL-005', member[:login], "#{member[:login]} belongs to #{member[:team_count]} teams")]
    end

    def check_pol006(team)
      return [] unless team[:secret_team] && team[:member_count] > 5

      [build_violation('POL-006', team[:name], "Secret team '#{team[:name]}' has #{team[:member_count]} members (limit: 5)")]
    end

    def build_violation(policy_id, subject, message)
      policy = POLICIES.find { |p| p[:id] == policy_id }
      {
        policy_id: policy_id,
        policy_name: policy[:name],
        severity: policy[:severity],
        subject: subject,
        message: message,
        framework_controls: policy[:framework_controls],
        detected_at: Time.now.iso8601
      }
    end
  end
end
