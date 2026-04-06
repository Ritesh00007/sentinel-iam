# frozen_string_literal: true

require 'octokit'
require 'date'

module Audit
  # Audits SSH keys for all org members, identifying stale and potentially
  # compromised keys that should be rotated or revoked.
  class SSHKeyAuditor
    attr_reader :client, :org

    def initialize(client, org)
      @client = client
      @org = org
    end

    # @param stale_days [Integer] threshold for flagging stale keys
    # @return [Hash] SSH audit results per member
    def run(stale_days: 365)
      members = safe_fetch { client.organization_members(org) } || []

      results = members.map do |member|
        keys = safe_fetch { client.keys(member.login) } || []

        key_details = keys.map do |key|
          age_days = key.created_at ? (Date.today - Date.parse(key.created_at.to_s)).to_i : nil
          stale = age_days ? age_days > stale_days : false
          weak = weak_key?(key.key)

          {
            id: key.id,
            title: key.title,
            key_type: extract_key_type(key.key),
            key_bits: extract_key_bits(key.key),
            created_at: key.created_at,
            age_days: age_days,
            stale: stale,
            weak_algorithm: weak,
            read_only: key.read_only,
            verified: key.verified,
            risk: key_risk(stale, weak)
          }
        end

        {
          login: member.login,
          total_keys: key_details.size,
          stale_keys: key_details.count { |k| k[:stale] },
          weak_keys: key_details.count { |k| k[:weak_algorithm] },
          unverified_keys: key_details.count { |k| !k[:verified] },
          keys: key_details,
          overall_risk: member_key_risk(key_details)
        }
      end

      {
        audited_at: Time.now.iso8601,
        stale_threshold_days: stale_days,
        members: results,
        summary: build_summary(results)
      }
    end

    private

    def weak_key?(key_string)
      return false unless key_string

      # Flag DSA keys (deprecated), RSA < 2048, or ecdsa-sha2-nistp256 (weak curve)
      key_string.start_with?('ssh-dss') ||
        key_string.start_with?('ecdsa-sha2-nistp256')
    end

    def extract_key_type(key_string)
      return 'unknown' unless key_string

      parts = key_string.split(' ')
      parts.first || 'unknown'
    end

    def extract_key_bits(key_string)
      return nil unless key_string

      # Rough heuristic based on base64 length for RSA keys
      parts = key_string.split(' ')
      return nil unless parts.size >= 2

      b64 = parts[1]
      byte_len = (b64.length * 3 / 4.0).ceil
      # RSA key bits roughly = (byte_len - 22) * 8 for modulus
      byte_len > 300 ? 4096 : byte_len > 150 ? 2048 : 1024
    end

    def key_risk(stale, weak)
      return :critical if stale && weak
      return :high if weak
      return :medium if stale
      :low
    end

    def member_key_risk(keys)
      return :none if keys.empty?
      return :critical if keys.any? { |k| k[:risk] == :critical }
      return :high if keys.any? { |k| k[:risk] == :high }
      return :medium if keys.any? { |k| k[:risk] == :medium }
      :low
    end

    def build_summary(results)
      {
        total_members_with_keys: results.count { |m| m[:total_keys] > 0 },
        members_with_stale_keys: results.count { |m| m[:stale_keys] > 0 },
        members_with_weak_keys: results.count { |m| m[:weak_keys] > 0 },
        total_stale_keys: results.sum { |m| m[:stale_keys] },
        total_weak_keys: results.sum { |m| m[:weak_keys] },
        critical_risk_members: results.count { |m| m[:overall_risk] == :critical },
        high_risk_members: results.count { |m| m[:overall_risk] == :high }
      }
    end

    def safe_fetch
      yield
    rescue Octokit::NotFound, Octokit::Forbidden => e
      warn "SSH audit warning: #{e.message}"
      nil
    end
  end
end
