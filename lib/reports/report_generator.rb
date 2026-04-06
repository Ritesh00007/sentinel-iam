# frozen_string_literal: true

require 'tty-table'
require 'pastel'
require 'json'
require 'csv'
require 'fileutils'
require 'rbac/policy_engine'

module Reports
  class ReportGenerator
    REPORT_DIR = File.join(__dir__, '..', '..', 'data', 'reports')

    attr_reader :org, :pastel

    def initialize(org)
      @org = org
      @pastel = Pastel.new
      FileUtils.mkdir_p(REPORT_DIR)
    end

    def render_entitlements(results, format: 'table', show_all: false)
      members = results[:members] || []
      members = members.select { |m| m[:risk_level] != :low || m[:stale] } unless show_all

      puts "\n#{pastel.bold.cyan("=== ENTITLEMENT AUDIT: #{org.upcase} ===")}"
      puts pastel.dim("Audited at: #{results[:audited_at]} | Stale threshold: #{results[:stale_threshold_days]} days\n")

      render_summary(results[:summary])

      case format
      when 'table' then render_members_table(members)
      when 'json'  then puts JSON.pretty_generate(results)
      when 'csv'   then render_members_csv(members)
      end

      render_violations(members)
    end

    def render_ssh_keys(results, format: 'table')
      puts "\n#{pastel.bold.cyan("=== SSH KEY AUDIT ===")}"

      risky = (results[:members] || []).select { |m| m[:overall_risk] != :none && m[:overall_risk] != :low }

      if risky.empty?
        puts pastel.green("✓ No high-risk SSH keys detected.")
        return
      end

      case format
      when 'table'
        table = TTY::Table.new(
          header: ['Login', 'Total Keys', 'Stale', 'Weak Algo', 'Unverified', 'Risk'],
          rows: risky.map do |m|
            [
              m[:login],
              m[:total_keys],
              colorize_count(m[:stale_keys]),
              colorize_count(m[:weak_keys]),
              colorize_count(m[:unverified_keys]),
              colorize_risk(m[:overall_risk])
            ]
          end
        )
        puts table.render(:unicode, padding: [0, 1])
      when 'json'
        puts JSON.pretty_generate(results)
      end

      ssh_summary = results[:summary]
      puts "\n#{pastel.bold('SSH Key Summary:')}"
      puts "  Members with stale keys : #{pastel.yellow(ssh_summary[:members_with_stale_keys].to_s)}"
      puts "  Members with weak keys  : #{pastel.red(ssh_summary[:members_with_weak_keys].to_s)}"
      puts "  Total stale keys        : #{pastel.yellow(ssh_summary[:total_stale_keys].to_s)}"
      puts "  Total weak keys         : #{pastel.red(ssh_summary[:total_weak_keys].to_s)}"
    end

    def generate_compliance_report(entitlements:, ssh_results:, violations:, framework:, quarter:)
      policy_engine = RBAC::PolicyEngine.new
      total_checks = (entitlements[:members]&.size || 0) * 4
      score = policy_engine.compliance_score(violations, total_checks)

      report = {
        meta: {
          org: org,
          framework: framework,
          quarter: quarter,
          generated_at: Time.now.iso8601,
          compliance_score: score
        },
        executive_summary: build_executive_summary(entitlements, violations, score),
        violations: violations,
        entitlement_summary: entitlements[:summary],
        ssh_summary: ssh_results[:summary],
        policy_catalog: policy_engine.policy_catalog,
        members_requiring_remediation: entitlements[:members]&.select { |m| m[:risk_level] != :low }
      }

      filename = "#{org}_#{framework}_#{quarter}_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
      path = File.join(REPORT_DIR, filename)
      File.write(path, JSON.pretty_generate(report))

      print_compliance_summary(report[:meta], violations, score)
      path
    end

    def save_report(data)
      filename = "#{org}_audit_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
      path = File.join(REPORT_DIR, filename)
      File.write(path, JSON.pretty_generate(data))
      puts pastel.dim("\nFull audit saved to: #{path}")
      path
    end

    private

    def render_summary(summary)
      return unless summary

      puts pastel.bold("Organization Summary:")
      puts "  Total members          : #{summary[:total_members]}"
      puts "  Admins                 : #{pastel.yellow(summary[:admin_count].to_s)}"
      puts "  Stale members          : #{pastel.yellow(summary[:stale_members].to_s)}"
      puts "  Stale admins           : #{pastel.red(summary[:stale_admins].to_s)}"
      puts "  Critical risk          : #{pastel.red(summary[:critical_risk].to_s)}"
      puts "  High risk              : #{pastel.yellow(summary[:high_risk].to_s)}"
      puts "  Total violations       : #{pastel.red(summary[:total_violations].to_s)}"
      puts "  Outside collaborators  : #{summary[:outside_collaborators]}"
      puts "  Over-shared repos      : #{pastel.yellow(summary[:over_shared_repos].to_s)}"
      puts ""
    end

    def render_members_table(members)
      return puts(pastel.green("✓ No over-privileged or stale members detected.")) if members.empty?

      table = TTY::Table.new(
        header: ['Login', 'Role', 'Last Active', 'Days Inactive', 'Teams', 'Admin Repos', 'Risk', 'Violations'],
        rows: members.map do |m|
          [
            m[:login],
            m[:is_admin] ? pastel.yellow('admin') : 'member',
            m[:last_active] ? m[:last_active].to_s[0..9] : pastel.red('never'),
            m[:days_since_active] || pastel.red('N/A'),
            m[:team_count],
            m[:repos_with_admin],
            colorize_risk(m[:risk_level]),
            m[:violations].size > 0 ? pastel.red(m[:violations].size.to_s) : pastel.green('0')
          ]
        end
      )
      puts table.render(:unicode, padding: [0, 1])
    end

    def render_members_csv(members)
      puts CSV.generate do |csv|
        csv << ['login', 'role', 'last_active', 'days_inactive', 'teams', 'admin_repos', 'risk', 'violations']
        members.each do |m|
          csv << [m[:login], m[:role], m[:last_active], m[:days_since_active], m[:team_count], m[:repos_with_admin], m[:risk_level], m[:violations].size]
        end
      end
    end

    def render_violations(members)
      all_violations = members.flat_map { |m| m[:violations] }
      return if all_violations.empty?

      puts "\n#{pastel.bold.red("Policy Violations (#{all_violations.size}):')}")
      all_violations.group_by { |v| v[:type] }.each do |type, viols|
        puts "  #{pastel.red("✗")} #{type} (#{viols.size} instances)"
      end
    end

    def print_compliance_summary(meta, violations, score)
      color = score >= 90 ? :green : score >= 70 ? :yellow : :red
      puts "\n#{pastel.bold.cyan("=== #{meta[:framework]} COMPLIANCE REPORT: #{meta[:quarter]} ===")}"
      puts "  Compliance Score : #{pastel.send(color, "#{score}%")}"
      puts "  Total Violations : #{pastel.red(violations.size.to_s)}"
      puts "  Critical         : #{violations.count { |v| v[:severity] == :critical }}"
      puts "  High             : #{violations.count { |v| v[:severity] == :high }}"
      puts "  Medium           : #{violations.count { |v| v[:severity] == :medium }}"
    end

    def build_executive_summary(entitlements, violations, score)
      summary = entitlements[:summary] || {}
      {
        compliance_score: score,
        total_violations: violations.size,
        critical_violations: violations.count { |v| v[:severity] == :critical },
        high_violations: violations.count { |v| v[:severity] == :high },
        stale_admins: summary[:stale_admins],
        recommendation: score >= 90 ? 'Access posture is healthy. Continue quarterly reviews.' :
                        score >= 70 ? 'Remediate high-severity violations within 30 days.' :
                        'Immediate remediation required. Escalate to security team.'
      }
    end

    def colorize_risk(level)
      case level
      when :critical then pastel.bold.red('CRITICAL')
      when :high     then pastel.red('HIGH')
      when :medium   then pastel.yellow('MEDIUM')
      when :low      then pastel.green('LOW')
      when :none     then pastel.dim('NONE')
      else level.to_s
      end
    end

    def colorize_count(count)
      count > 0 ? pastel.red(count.to_s) : pastel.green('0')
    end
  end
end
