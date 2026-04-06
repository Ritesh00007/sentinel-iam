# frozen_string_literal: true

require 'octokit'
require 'date'

module Audit
  # Audits GitHub Organization member entitlements for over-privileged users
  # and stale access patterns using the Octokit GitHub API client.
  class EntitlementAuditor
    RISK_LEVELS = { critical: 3, high: 2, medium: 1, low: 0 }.freeze

    attr_reader :client, :org

    def initialize(client, org)
      @client = client
      @org = org
    end

    # Run the full entitlement audit
    # @param stale_days [Integer] threshold for flagging stale access
    # @return [Hash] audit results with members, teams, repos, violations
    def run(stale_days: 90)
      {
        org: org,
        audited_at: Time.now.iso8601,
        stale_threshold_days: stale_days,
        members: audit_members(stale_days),
        teams: audit_teams,
        repos: audit_repos,
        outside_collaborators: audit_outside_collaborators(stale_days),
        summary: {}
      }.tap { |r| r[:summary] = build_summary(r) }
    end

    private

    def audit_members(stale_days)
      members = client.organization_members(org, role: 'all')
      admins = client.organization_members(org, role: 'admin').map(&:login).to_set

      members.map do |member|
        login = member.login
        user_detail = safe_fetch { client.user(login) }
        last_active = derive_last_active(login)
        stale = stale?(last_active, stale_days)
        is_admin = admins.include?(login)
        team_memberships = member_teams(login)
        repo_access = member_repo_access(login)

        {
          login: login,
          name: user_detail&.name,
          email: user_detail&.email,
          role: is_admin ? 'admin' : 'member',
          is_admin: is_admin,
          last_active: last_active,
          stale: stale,
          days_since_active: days_since(last_active),
          team_count: team_memberships.size,
          teams: team_memberships,
          repo_count: repo_access.size,
          repos_with_admin: repo_access.count { |r| r[:permission] == 'admin' },
          risk_level: calculate_risk(is_admin, stale, repo_access),
          violations: detect_violations(login, is_admin, stale, repo_access, team_memberships)
        }
      end
    end

    def audit_teams
      client.organization_teams(org).map do |team|
        members = safe_fetch { client.team_members(team.id) } || []
        repos = safe_fetch { client.team_repositories(team.id) } || []

        {
          id: team.id,
          name: team.name,
          slug: team.slug,
          privacy: team.privacy,
          permission: team.permission,
          member_count: members.size,
          repo_count: repos.size,
          has_admin_permission: team.permission == 'admin',
          secret_team: team.privacy == 'secret'
        }
      end
    end

    def audit_repos
      client.organization_repositories(org).map do |repo|
        collaborators = safe_fetch { client.collaborators(repo.full_name) } || []
        admin_collabs = collaborators.select { |c| c.permissions&.admin }

        {
          name: repo.name,
          full_name: repo.full_name,
          private: repo.private,
          visibility: repo.visibility,
          collaborator_count: collaborators.size,
          admin_collaborator_count: admin_collabs.size,
          over_shared: admin_collabs.size > 3,
          archived: repo.archived,
          pushed_at: repo.pushed_at
        }
      end
    end

    def audit_outside_collaborators(stale_days)
      collabs = safe_fetch { client.outside_collaborators(org) } || []
      collabs.map do |collab|
        last_active = derive_last_active(collab.login)
        {
          login: collab.login,
          last_active: last_active,
          stale: stale?(last_active, stale_days),
          days_since_active: days_since(last_active),
          risk_level: :high  # outside collaborators always flagged as elevated risk
        }
      end
    end

    def member_teams(login)
      client.organization_teams(org).select do |team|
        members = safe_fetch { client.team_members(team.id) } || []
        members.any? { |m| m.login == login }
      end.map { |t| { name: t.name, permission: t.permission } }
    rescue StandardError
      []
    end

    def member_repo_access(login)
      repos = safe_fetch { client.organization_repositories(org) } || []
      repos.filter_map do |repo|
        perm = safe_fetch { client.permission_level(repo.full_name, login) }
        next unless perm

        {
          repo: repo.name,
          permission: perm.permission
        }
      end
    end

    def derive_last_active(login)
      events = safe_fetch { client.user_public_events(login) } || []
      return nil if events.empty?

      events.first.created_at
    rescue StandardError
      nil
    end

    def calculate_risk(is_admin, stale, repo_access)
      score = 0
      score += 3 if is_admin
      score += 2 if stale
      score += repo_access.count { |r| r[:permission] == 'admin' }

      case score
      when 0..1 then :low
      when 2..3 then :medium
      when 4..5 then :high
      else :critical
      end
    end

    def detect_violations(login, is_admin, stale, repo_access, teams)
      violations = []
      violations << { type: 'STALE_ADMIN', severity: :critical, message: "Admin user has been inactive > threshold" } if is_admin && stale
      violations << { type: 'STALE_ACCESS', severity: :medium, message: "User inactive beyond retention threshold" } if stale && !is_admin
      violations << { type: 'EXCESS_ADMIN_REPOS', severity: :high, message: "User has admin on #{repo_access.count { |r| r[:permission] == 'admin' }} repos" } if repo_access.count { |r| r[:permission] == 'admin' } > 5
      violations << { type: 'OVER_TEAMED', severity: :low, message: "Member of #{teams.size} teams — review for least-privilege" } if teams.size > 10
      violations
    end

    def build_summary(results)
      members = results[:members]
      {
        total_members: members.size,
        admin_count: members.count { |m| m[:is_admin] },
        stale_members: members.count { |m| m[:stale] },
        stale_admins: members.count { |m| m[:is_admin] && m[:stale] },
        critical_risk: members.count { |m| m[:risk_level] == :critical },
        high_risk: members.count { |m| m[:risk_level] == :high },
        total_violations: members.sum { |m| m[:violations].size },
        outside_collaborators: results[:outside_collaborators].size,
        stale_outside_collaborators: results[:outside_collaborators].count { |c| c[:stale] },
        total_teams: results[:teams].size,
        total_repos: results[:repos].size,
        over_shared_repos: results[:repos].count { |r| r[:over_shared] }
      }
    end

    def stale?(last_active, days)
      return true if last_active.nil?

      (Date.today - Date.parse(last_active.to_s)).to_i > days
    end

    def days_since(last_active)
      return nil if last_active.nil?

      (Date.today - Date.parse(last_active.to_s)).to_i
    end

    def safe_fetch
      yield
    rescue Octokit::NotFound, Octokit::Forbidden, Octokit::TooManyRequests => e
      warn "API warning: #{e.message}"
      nil
    end
  end
end
