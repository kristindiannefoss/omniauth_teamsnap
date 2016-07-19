require 'omniauth/strategies/oauth2'
# require 'omniauth/facebook/signed_request'
require 'openssl'
require 'rack/utils' # <-- ?? -.^
require 'uri'

module OmniAuth
  module Strategies
    class TeamSnap < OmniAuth::Strategies::OAuth2
      class NoAuthorizationCodeError < StandardError; end

      DEFAULT_SCOPE = 'read'

      option :name, 'team_snap'
      option :fields, [:name, :username]
      option :uid_field, :email

      option :client_options, {
        site: 'https://auth.teamsnap.com',
        authorize_url: "https://auth.teamsnap.com/oauth/authorize",
        token_url: 'https://auth.teamsnap.com/oauth/token',
        client_id:
        'x',
        client_secret:
        'y',
      }

      option :access_token_options, {
        header_format: 'Authorization: Bearer %s',
        param_name: 'access_token'
      }


      # possibly need: client_id, redirect_uri, response_type
      option :authorize_options, [:scope, :client_id, :redirect_uri, :response_type]

      uid { raw_info['id'] }

      info do
        binding.pry
        prune!({
          'nickname' => raw_info['username'],
          'email' => raw_info['email'],
          'name' => raw_info['name'],
          'first_name' => raw_info['first_name'],
          'last_name' => raw_info['last_name'],
          'image' => image_url(uid, options),
          'description' => raw_info['bio'],
          'urls' => {
            'Facebook' => raw_info['link'],
            'Website' => raw_info['website']
          },
          'location' => (raw_info['location'] || {})['name'],
          'verified' => raw_info['verified']
        })
      end

      extra do
        binding.pry
        hash = {}
        hash['raw_info'] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        binding.pry
        @raw_info ||= access_token.get('me', info_options).parsed || {}
      end

      def info_options
        binding.pry
        params = {appsecret_proof: appsecret_proof}
        params.merge!({fields: (options[:info_fields] || 'name,email')})
        params.merge!({locale: options[:locale]}) if options[:locale]

        { params: params }
      end

      def callback_url
        full_host + script_name + callback_path
      end


      def callback_phase
        with_authorization_code! do
          super
        end
      rescue NoAuthorizationCodeError => e
        fail!(:no_authorization_code, e)
      # rescue OmniAuth::Facebook::SignedRequest::UnknownSignatureAlgorithmError => e
        # fail!(:unknown_signature_algorithm, e)
      end

      def access_token_options
        binding.pry
        # options.access_token_options
        #        .map { |k, v| [k.to_sym, v] }
        #        .to_h
        options.access_token_options
               .inject({}) { |h, (k,v)| h[k.to_sym] = v; h }
      end

      # delete?
      def authorize_params
        super.tap do |params|
          %w[display scope auth_type].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      protected

      def build_access_token
        super.tap do |token|
          opts = token.options
          opts.merge!(access_token_options)
          opts.merge!(redirect_uri: 'http://localhost:3000/auth/team_snap/callback')
        end
      end

      private

      def signed_request_from_cookie
        binding.pry
        @signed_request_from_cookie ||= raw_signed_request_from_cookie && OmniAuth::Facebook::SignedRequest.parse(raw_signed_request_from_cookie, client.secret)
      end

      def raw_signed_request_from_cookie
        binding.pry
        request.cookies["fbsr_#{client.id}"]
      end

      # Picks the authorization code in order, from:
      #
      # 1. The request 'code' param (manual callback from standard server-side flow)
      # 2. A signed request from cookie (passed from the client during the client-side flow)
      def with_authorization_code!
        if request.params.key?('code')
          yield
        elsif code_from_signed_request = signed_request_from_cookie && signed_request_from_cookie['code']
          request.params['code'] = code_from_signed_request
          @authorization_code_from_signed_request_in_cookie = true
          # NOTE The code from the signed fbsr_XXX cookie is set by the FB JS SDK will confirm that the identity of the
          #      user contained in the signed request matches the user loading the app.
          original_provider_ignores_state = options.provider_ignores_state
          options.provider_ignores_state = true
          begin
            yield
          ensure
            request.params.delete('code')
            @authorization_code_from_signed_request_in_cookie = false
            options.provider_ignores_state = original_provider_ignores_state
          end
        else
          raise NoAuthorizationCodeError, 'must pass either a `code` (via URL or by an `fbsr_XXX` signed request cookie)'
        end
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def image_url(uid, options)
        binding.pry
        uri_class = options[:secure_image_url] ? URI::HTTPS : URI::HTTP
        site_uri = URI.parse(client.site)
        url = uri_class.build({host: site_uri.host, path: "#{site_uri.path}/#{uid}/picture"})

        query = if options[:image_size].is_a?(String) || options[:image_size].is_a?(Symbol)
          { type: options[:image_size] }
        elsif options[:image_size].is_a?(Hash)
          options[:image_size]
        end
        url.query = Rack::Utils.build_query(query) if query

        url.to_s
      end

      def appsecret_proof
        binding.pry
        @appsecret_proof ||= OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, client.secret, access_token.token)
      end
    end
  end
end
