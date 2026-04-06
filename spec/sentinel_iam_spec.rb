# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Audit::EntitlementAuditor do
  let(:org) { 'test-org' }
  let(:client) { instance_double(Octokit::Client) }
  let(:auditor) { described_class.new(client, org) }

  let(:mock_member) do
    double(login: 'jdoe', name: 'Jane Doe', email: 'jdoe@example.com',
           created_at: Time.now - (200 * 86400))
  end

  let(:mock_admin) do
    double(login: 'admin-user')
  end

  before do
    allow(client).to receive(:organization_members).with(org, role: 'all').and_return([mock_member])
    allow(client).to receive(:organization_members).with(org, role: 'admin').and_return([mock_admin])
    allow(client).to receive(:user).with('jdoe').and_return(mock_member)
    allow(client).to receive(:user_public_events).with('jdoe').and_return([
      double(created_at: Time.now - (100 * 86400))
    ])
    allow(client).to receive(:organization_teams).with(org).and_return([])
    allow(client).to receive(:organization_repositories).with(org).and_return([])
    allow(client).to receive(:outside_collaborators).with(org).and_return([])
  end

  describe '#run' do
    subject(:result) { auditor.run(stale_days: 90) }

    it 'returns audit results hash' do
      expect(result).to include(:org, :audited_at, :members, :summary)
    end

    it 'includes org name' do
      expect(result[:org]).to eq(org)
    end

    it 'includes audited_at timestamp' do
      expect(result[:audited_at]).to match(/\d{4}-\d{2}-\d{2}/)
    end

    it 'audits members' do
      expect(result[:members]).to be_an(Array)
      expect(result[:members].first[:login]).to eq('jdoe')
    end

    it 'correctly identifies non-admin members' do
      expect(result[:members].first[:is_admin]).to be false
    end

    it 'detects stale access when inactive > threshold' do
      expect(result[:members].first[:stale]).to be true
    end

    it 'builds summary with correct totals' do
      summary = result[:summary]
      expect(summary[:total_members]).to eq(1)
      expect(summary[:stale_members]).to eq(1)
    end
  end
end

RSpec.describe Audit::SSHKeyAuditor do
  let(:org) { 'test-org' }
  let(:client) { instance_double(Octokit::Client) }
  let(:auditor) { described_class.new(client, org) }

  let(:mock_member) { double(login: 'jdoe') }
  let(:old_key) do
    double(
      id: 1,
      title: 'old-laptop',
      key: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB' + 'A' * 250,
      created_at: Time.now - (400 * 86400),
      read_only: false,
      verified: true
    )
  end

  let(:weak_key) do
    double(
      id: 2,
      title: 'weak-dsa',
      key: 'ssh-dss AAAAB3NzaC1kc3MAAA' + 'B' * 100,
      created_at: Time.now - (30 * 86400),
      read_only: true,
      verified: false
    )
  end

  before do
    allow(client).to receive(:organization_members).with(org).and_return([mock_member])
    allow(client).to receive(:keys).with('jdoe').and_return([old_key, weak_key])
  end

  describe '#run' do
    subject(:result) { auditor.run(stale_days: 365) }

    it 'returns ssh audit results' do
      expect(result).to include(:audited_at, :members, :summary)
    end

    it 'detects stale keys' do
      member = result[:members].first
      expect(member[:stale_keys]).to eq(1)
    end

    it 'detects weak algorithm keys' do
      member = result[:members].first
      expect(member[:weak_keys]).to eq(1)
    end

    it 'detects unverified keys' do
      member = result[:members].first
      expect(member[:unverified_keys]).to eq(1)
    end

    it 'calculates overall risk correctly' do
      member = result[:members].first
      expect(member[:overall_risk]).to eq(:high)
    end
  end
end

RSpec.describe RBAC::PolicyEngine do
  let(:engine) { described_class.new }

  let(:stale_admin_results) do
    {
      members: [{
        login: 'stale-admin',
        is_admin: true,
        stale: true,
        days_since_active: 120,
        repos_with_admin: 2,
        team_count: 3,
        violations: []
      }],
      teams: [],
      outside_collaborators: []
    }
  end

  describe '#evaluate' do
    it 'returns array of violations' do
      expect(engine.evaluate(stale_admin_results)).to be_an(Array)
    end

    it 'flags POL-001 for stale admins' do
      violations = engine.evaluate(stale_admin_results)
      expect(violations.any? { |v| v[:policy_id] == 'POL-001' }).to be true
    end

    it 'assigns critical severity to stale admin violation' do
      violations = engine.evaluate(stale_admin_results)
      pol001 = violations.find { |v| v[:policy_id] == 'POL-001' }
      expect(pol001[:severity]).to eq(:critical)
    end

    it 'includes framework controls in violation' do
      violations = engine.evaluate(stale_admin_results)
      pol001 = violations.find { |v| v[:policy_id] == 'POL-001' }
      expect(pol001[:framework_controls]).to include('SOC2')
    end
  end

  describe '#compliance_score' do
    it 'returns 100 for zero violations' do
      expect(engine.compliance_score([], 10)).to eq(100.0)
    end

    it 'returns 0 for all violations' do
      violations = Array.new(10, {})
      expect(engine.compliance_score(violations, 10)).to eq(0.0)
    end

    it 'returns 50 for half violations' do
      violations = Array.new(5, {})
      expect(engine.compliance_score(violations, 10)).to eq(50.0)
    end
  end

  describe '#policy_catalog' do
    it 'returns all defined policies' do
      expect(engine.policy_catalog.size).to eq(6)
    end

    it 'includes required fields' do
      engine.policy_catalog.each do |policy|
        expect(policy).to include(:id, :name, :severity, :framework_controls)
      end
    end
  end
end
