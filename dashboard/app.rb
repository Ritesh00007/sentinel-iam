# frozen_string_literal: true

require 'sinatra/base'
require 'sinatra/json'
require 'json'
require 'octokit'
require 'audit/entitlement_auditor'
require 'audit/ssh_key_auditor'
require 'rbac/policy_engine'

module SentinelIAM
  module Dashboard
    class App < Sinatra::Base
      set :views, File.join(__dir__, 'views')
      set :public_folder, File.join(__dir__, 'public')
      set :bind, '0.0.0.0'

      configure do
        enable :logging
      end

      helpers do
        def client
          token = ENV['GITHUB_TOKEN']
          halt 401, json(error: 'GITHUB_TOKEN not set') unless token
          @client ||= Octokit::Client.new(access_token: token, auto_paginate: true, per_page: 100)
        end

        def org
          params[:org] || ENV['GITHUB_ORG'] || settings.respond_to?(:org) ? settings.org : nil
        end
      end

      get '/' do
        erb :index
      end

      # API: Full audit results
      get '/api/audit' do
        content_type :json
        halt 400, json(error: 'org parameter required') unless org

        auditor = Audit::EntitlementAuditor.new(client, org)
        ssh_auditor = Audit::SSHKeyAuditor.new(client, org)
        policy_engine = RBAC::PolicyEngine.new

        entitlements = auditor.run(stale_days: 90)
        ssh_results = ssh_auditor.run(stale_days: 365)
        violations = policy_engine.evaluate(entitlements)
        score = policy_engine.compliance_score(violations, (entitlements[:members]&.size || 0) * 4)

        json({
          org: org,
          audited_at: Time.now.iso8601,
          compliance_score: score,
          summary: entitlements[:summary],
          members: entitlements[:members],
          teams: entitlements[:teams],
          outside_collaborators: entitlements[:outside_collaborators],
          ssh_summary: ssh_results[:summary],
          ssh_members: ssh_results[:members],
          violations: violations,
          policy_catalog: policy_engine.policy_catalog
        })
      rescue Octokit::Unauthorized
        halt 401, json(error: 'Invalid GitHub token')
      rescue => e
        halt 500, json(error: e.message)
      end

      # API: Members only
      get '/api/members' do
        content_type :json
        halt 400, json(error: 'org parameter required') unless org

        auditor = Audit::EntitlementAuditor.new(client, org)
        results = auditor.run(stale_days: (params[:stale_days] || 90).to_i)
        json(results[:members])
      end

      # API: Policy violations
      get '/api/violations' do
        content_type :json
        halt 400, json(error: 'org parameter required') unless org

        auditor = Audit::EntitlementAuditor.new(client, org)
        policy_engine = RBAC::PolicyEngine.new
        entitlements = auditor.run(stale_days: 90)
        violations = policy_engine.evaluate(entitlements)
        json(violations)
      end

      # API: SSH audit
      get '/api/ssh' do
        content_type :json
        halt 400, json(error: 'org parameter required') unless org

        auditor = Audit::SSHKeyAuditor.new(client, org)
        results = auditor.run(stale_days: (params[:stale_days] || 365).to_i)
        json(results)
      end

      # API: Saved compliance reports
      get '/api/reports' do
        content_type :json
        report_dir = File.join(__dir__, '..', '..', 'data', 'reports')
        reports = Dir.glob("#{report_dir}/*.json").map do |f|
          {
            filename: File.basename(f),
            size: File.size(f),
            created_at: File.mtime(f).iso8601
          }
        end.sort_by { |r| r[:created_at] }.reverse
        json(reports)
      end

      run! if app_file == $0
    end
  end
end
