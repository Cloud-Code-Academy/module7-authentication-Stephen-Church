/**
 * Service class to handle OAuth 2.0 authentication with Salesforce
 * STUDENT VERSION - Complete the method implementations
 */
public class SFAuthenticationManager {
	// Endpoint for token requests
	private static final String TOKEN_ENDPOINT = '/services/oauth2/token';
	private static final String AUTHORIZE_ENDPOINT = '/services/oauth2/authorize';
	private static final String PKCE_GENERATOR_ENDPOINT = '/services/oauth2/pkce/generator';

	// Configuration values
	public static final String DEFAULT_CLIENT_ID = '[REDACTED]';
	public static final String DEFAULT_CLIENT_SECRET = '[REDACTED]';
	public static final String DEFAULT_LOGIN_URL = 'https://orgfarm-ab43aa86c2-dev-ed.develop.my.salesforce.com';
	public static final String DEFAULT_REDIRECT_URL = 'https://orgfarm-ab43aa86c2-dev-ed.develop.my.salesforce-sites.com/callback';

	/**
	 * Central method to make OAuth token requests
	 * TODO: Complete this method implementation
	 * @param params Map of parameters to include in the request
	 * @param tokenUrl The full URL to the token endpoint
	 * @return Authentication response with token details or error
	 */
	private static AuthResponse makeTokenRequest(Map<String, String> params, String tokenUrl) {

		AuthResponse authResponse = new AuthResponse();

		try {

			List<String> bodyParts = new List<String>();
			for (String key : params.keySet()) {
				bodyParts.add(EncodingUtil.urlEncode(key, 'UTF-8') + '=' + EncodingUtil.urlEncode(params.get(key), 'UTF-8'));
			}

			HttpRequest req = new HttpRequest();
			req.setEndpoint(tokenUrl);
			req.setMethod('POST');
			req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
			req.setBody(String.join(bodyParts, '&'));

			Http http = new Http();
			HttpResponse res = http.send(req);

			Map<String, Object> json = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());

			if (res.getStatusCode() >= 200 && res.getStatusCode() < 300) {
				authResponse.isSuccess = true;
				authResponse.accessToken = (String) json.get('access_token');
				authResponse.refreshToken = (String) json.get('refresh_token');
				authResponse.instanceUrl = (String) json.get('instance_url');
				authResponse.tokenType = (String) json.get('token_type');
				authResponse.expiresIn = json.containsKey('expires_in') ? Integer.valueOf(String.valueOf(json.get('expires_in'))) : null;
			} else {
				authResponse.isSuccess = false;
				authResponse.errorMessage = 'HTTP Error: ' + res.getStatus();
				authResponse.errorDetails = res.getBody();
			}
		} catch (Exception e) {
			authResponse.isSuccess = false;
			authResponse.errorMessage = e.getMessage();
		}

		return authResponse;
	}

	/**
	 * Authenticate using username and password flow (grant_type=password)
	 * TODO: Complete this method implementation
	 * @param username Username for the org
	 * @param password Password + Security Token
	 * @param securityToken Security Token
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithPassword(
		String username,
		String password,
		String securityToken
	) {

		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'password',
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'username' => username,
			'password' => password + securityToken
		};

		return makeTokenRequest(params, DEFAULT_LOGIN_URL + TOKEN_ENDPOINT);
	}

	/**
	 * Authenticate using client credentials flow (grant_type=client_credentials)
	 * TODO: Complete this method implementation
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithClientCredentials() {

		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'client_credentials',
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET
		};

		return makeTokenRequest(params, DEFAULT_LOGIN_URL + TOKEN_ENDPOINT);
	}

	/**
	 * JWT Bearer Token Flow authentication
	 * TODO: Complete this method implementation
	 * @param username Username for the org
	 * @return Authentication response with token details or error
	 */
	public static AuthResponse authenticateWithJWT(String username) {

		AuthResponse authResponse = new AuthResponse();

		try {
			Auth.JWT jwt = new Auth.JWT();
			jwt.setSub(username);
			jwt.setAud('https://login.salesforce.com');
			jwt.setIss(DEFAULT_CLIENT_ID);

			Auth.JWS jws = new Auth.JWS(jwt, 'jwtsource');
			String token = jws.getCompactSerialization();
			String tokenEndpoint = DEFAULT_LOGIN_URL + TOKEN_ENDPOINT;

			Auth.JWTBearerTokenExchange bearer = new Auth.JWTBearerTokenExchange(tokenEndpoint, jws);

			String accessToken = bearer.getAccessToken();

			authResponse.isSuccess = true;
			authResponse.accessToken = accessToken;
			authResponse.instanceUrl = DEFAULT_LOGIN_URL;

		} catch (Exception e) {
			authResponse.isSuccess = false;
			authResponse.errorMessage = e.getMessage();
		}
		return authResponse;
	}

	/**
	 * Generate the authorization URL for Web Server Flow
	 * TODO: Complete this method implementation
	 * @param state Optional state parameter for CSRF protection
	 * @return Full authorization URL
	 */
	@AuraEnabled
	public static String generateAuthorizationUrl(String state) {

		String url = DEFAULT_LOGIN_URL + AUTHORIZE_ENDPOINT +
			'?response_type=code' +
			'&client_id=' + EncodingUtil.urlEncode(DEFAULT_CLIENT_ID, 'UTF-8') +
			'&redirect_uri=' + EncodingUtil.urlEncode(DEFAULT_REDIRECT_URL, 'UTF-8');

		if (String.isNotBlank(state)) {
			url += '&state=' + EncodingUtil.urlEncode(state, 'UTF-8');
		}
		return url;
	}

	/**
	 * Generate PKCE data for OAuth 2.0 authorization
	 * TODO: Complete this method implementation
	 * @return PkceResponse containing code verifier and challenge
	 */
	@AuraEnabled
	public static PkceResponse generatePkceData() {

		PkceResponse pkceResponse = new PkceResponse();

		try {
			String codeVerifier = EncodingUtil.base64Encode(Crypto.generateAesKey(256))
				.replace('+', '-')
				.replace('/', '_')
				.replace('=', '');

			Blob digest = Crypto.generateDigest('SHA-256', Blob.valueOf(codeVerifier));

			String codeChallenge = EncodingUtil.base64Encode(digest)
				.replace('+', '-')
				.replace('/', '_')
				.replace('=', '');

			pkceResponse.isSuccess = true;
			pkceResponse.codeVerifier = codeVerifier;
			pkceResponse.codeChallenge = codeChallenge;
			pkceResponse.codeChallengeMethod = 'S256';

		} catch (Exception e) {
			pkceResponse.isSuccess = false;
			pkceResponse.errorMessage = e.getMessage();
		}

		return pkceResponse;	
	}

	/**
	 * Generate authorization URL with PKCE support
	 * TODO: Complete this method implementation
	 * @param usePkce Whether to include PKCE parameters
	 * @param codeChallenge Code challenge from PKCE generation
	 * @param codeChallengeMethod Code challenge method from PKCE generation
	 * @return Full authorization URL with PKCE parameters if requested
	 */
	@AuraEnabled
	public static String generateAuthorizationUrlWithPkce(
		Boolean usePkce,
		String codeChallenge,
		String codeChallengeMethod
	) {

		String url = generateAuthorizationUrl(null);

		if (usePkce) {
			url += '&code_challenge=' + EncodingUtil.urlEncode(codeChallenge, 'UTF-8');
			url += '&code_challenge_method=' + EncodingUtil.urlEncode(codeChallengeMethod, 'UTF-8');
		}

		return url;
	}

	/**
	 * Exchange authorization code for access token (grant_type=authorization_code)
	 * TODO: Complete this method implementation
	 * @param code Authorization code received from the redirect
	 * @return Authentication response with token details or error
	 */
	@AuraEnabled
	public static AuthResponse exchangeCodeForToken(String code) {

		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'authorization_code',
			'code' => code,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET,
			'redirect_uri' => DEFAULT_REDIRECT_URL
		};

		return makeTokenRequest(params, DEFAULT_LOGIN_URL + TOKEN_ENDPOINT);
	}

	/**
	 * Exchange authorization code for access token with PKCE support
	 * TODO: Complete this method implementation
	 * @param code Authorization code received from the redirect
	 * @param codeVerifier Code verifier for PKCE
	 * @return Authentication response with token details or error
	 */
	@AuraEnabled
	public static AuthResponse exchangeCodeForTokenWithPkce(String code, String codeVerifier) {

		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'authorization_code',
			'code' => code,
			'client_id' => DEFAULT_CLIENT_ID,
			'redirect_uri' => DEFAULT_REDIRECT_URL
		};

		if (String.isNotBlank(codeVerifier)) {
			params.put('code_verifier', codeVerifier);
		}

		return makeTokenRequest(params, DEFAULT_LOGIN_URL + TOKEN_ENDPOINT);
	}

	/**
	 * Refresh an existing access token using a refresh token
	 * Extra Credit: Implement this method
	 * TODO: Complete this method implementation
	 * @param refreshToken The refresh token from a previous authentication
	 * @return Authentication response with new token details or error
	 */
	public static AuthResponse refreshToken(String refreshToken) {

		Map<String, String> params = new Map<String, String>{
			'grant_type' => 'refresh_token',
			'refresh_token' => refreshToken,
			'client_id' => DEFAULT_CLIENT_ID,
			'client_secret' => DEFAULT_CLIENT_SECRET
		};

		return makeTokenRequest(params, DEFAULT_LOGIN_URL + TOKEN_ENDPOINT);
	}

	/**
	 * Class to encapsulate authentication response
	 */
	public class AuthResponse {
		@AuraEnabled
		public Boolean isSuccess;
		@AuraEnabled
		public String accessToken;
		@AuraEnabled
		public String refreshToken;
		@AuraEnabled
		public String instanceUrl;
		@AuraEnabled
		public String tokenType;
		@AuraEnabled
		public Integer expiresIn;
		@AuraEnabled
		public String errorMessage;
		@AuraEnabled
		public String errorDetails;
	}

	/**
	 * Class to encapsulate PKCE response
	 */
	public class PkceResponse {
		@AuraEnabled
		public Boolean isSuccess;
		@AuraEnabled
		public String codeVerifier;
		@AuraEnabled
		public String codeChallenge;
		@AuraEnabled
		public String codeChallengeMethod;
		@AuraEnabled
		public String errorMessage;
		@AuraEnabled
		public String errorDetails;
	}
}
