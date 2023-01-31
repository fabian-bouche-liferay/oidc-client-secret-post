package com.liferay.samples.fbo.oidc.client.secret.post;

import com.liferay.oauth.client.persistence.model.OAuthClientEntry;
import com.liferay.oauth.client.persistence.service.OAuthClientEntryLocalService;
import com.liferay.petra.function.UnsafeConsumer;
import com.liferay.petra.string.StringBundler;
import com.liferay.petra.string.StringPool;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.service.ServiceContextFactory;
import com.liferay.portal.kernel.util.HashMapBuilder;
import com.liferay.portal.kernel.util.Portal;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectAuthenticationHandler;
import com.liferay.portal.security.sso.openid.connect.OpenIdConnectServiceException;
import com.liferay.portal.security.sso.openid.connect.constants.OpenIdConnectConstants;
import com.liferay.portal.security.sso.openid.connect.constants.OpenIdConnectWebKeys;
import com.liferay.portal.security.sso.openid.connect.internal.AuthorizationServerMetadataResolver;
import com.liferay.portal.security.sso.openid.connect.internal.OIDCUserInfoProcessor;
import com.liferay.portal.security.sso.openid.connect.internal.OpenIdConnectAuthenticationHandlerImpl;
import com.liferay.portal.security.sso.openid.connect.internal.OpenIdConnectAuthenticationSession;
import com.liferay.portal.security.sso.openid.connect.internal.OpenIdConnectSessionImpl;
import com.liferay.portal.security.sso.openid.connect.internal.configuration.admin.service.OpenIdConnectProviderManagedServiceFactory;
import com.liferay.portal.security.sso.openid.connect.internal.session.manager.OfflineOpenIdConnectSessionManager;
import com.liferay.portal.security.sso.openid.connect.internal.util.OpenIdConnectRequestParametersUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONObject;

@Component(
		immediate = true,
	    property = {
	            "service.ranking:Integer=100"
	        },
		service = OpenIdConnectAuthenticationHandler.class
		)
public class ClientSecretPostOpenIdConnectAuthenticationHandlerImpl implements OpenIdConnectAuthenticationHandler {

	private final static Logger _log = LoggerFactory.getLogger(ClientSecretPostOpenIdConnectAuthenticationHandlerImpl.class);
	
	/*
	 * BEGIN: Copy methods from OpenIdConnectTokenRequestUtil
	 */
	private OIDCTokens request(
			AuthenticationSuccessResponse authenticationSuccessResponse,
			Nonce nonce, OIDCClientInformation oidcClientInformation,
			OIDCProviderMetadata oidcProviderMetadata, URI redirectURI,
			String tokenRequestParametersJSON)
		throws Exception {

		AuthorizationGrant authorizationCodeGrant = new AuthorizationCodeGrant(
			authenticationSuccessResponse.getAuthorizationCode(), redirectURI);

		return _requestOIDCTokens(
			authorizationCodeGrant, nonce, oidcClientInformation,
			oidcProviderMetadata,
			JSONObjectUtils.parse(tokenRequestParametersJSON));
	}

	private OIDCTokens request(
			OIDCClientInformation oidcClientInformation,
			OIDCProviderMetadata oidcProviderMetadata,
			RefreshToken refreshToken, String tokenRequestParametersJSON)
		throws Exception {

		AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(
			refreshToken);

		return _requestOIDCTokens(
			refreshTokenGrant, null, oidcClientInformation,
			oidcProviderMetadata,
			JSONObjectUtils.parse(tokenRequestParametersJSON));
	}

	private OIDCTokens _requestOIDCTokens(
			AuthorizationGrant authorizationCodeGrant, Nonce nonce,
			OIDCClientInformation oidcClientInformation,
			OIDCProviderMetadata oidcProviderMetadata,
			JSONObject tokenRequestParametersJSONObject)
		throws Exception {

		URI uri = oidcProviderMetadata.getTokenEndpointURI();

		ClientID clientID = oidcClientInformation.getID();
		Secret secret = oidcClientInformation.getSecret();

		Map<String, List<String>> customRequestParametersMap = new HashMap<>();

		OpenIdConnectRequestParametersUtil.consumeCustomRequestParameters(
			(key, values) -> customRequestParametersMap.put(
				key, Arrays.asList(values)),
			tokenRequestParametersJSONObject);

		// Replacing ClientSecretBasic with ClientSecretPost
		TokenRequest tokenRequest = new TokenRequest(
			uri, new ClientSecretPost(clientID, secret),
			authorizationCodeGrant, null,
			Arrays.asList(
				OpenIdConnectRequestParametersUtil.getResourceURIs(
					tokenRequestParametersJSONObject)),
			customRequestParametersMap);

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();

		if (_log.isDebugEnabled()) {
			_log.debug("Query: " + httpRequest.getQuery());
		}

		try {
			HTTPResponse httpResponse = httpRequest.send();

			TokenResponse tokenResponse = OIDCTokenResponseParser.parse(
				httpResponse);

			if (tokenResponse instanceof TokenErrorResponse) {
				TokenErrorResponse tokenErrorResponse =
					(TokenErrorResponse)tokenResponse;

				ErrorObject errorObject = tokenErrorResponse.getErrorObject();

				JSONObject jsonObject = errorObject.toJSONObject();

				throw new OpenIdConnectServiceException.TokenException(
					jsonObject.toString());
			}

			OIDCTokenResponse oidcTokenResponse =
				(OIDCTokenResponse)tokenResponse;

			OIDCTokens oidcTokens = oidcTokenResponse.getOIDCTokens();

			_validate(
				clientID, secret, nonce,
				oidcClientInformation.getOIDCMetadata(), oidcProviderMetadata,
				oidcTokens);

			return oidcTokens;
		}
		catch (IOException ioException) {
			throw new OpenIdConnectServiceException.TokenException(
				StringBundler.concat(
					"Unable to get tokens from ", uri, ": ",
					ioException.getMessage()),
				ioException);
		}
		catch (ParseException parseException) {
			throw new OpenIdConnectServiceException.TokenException(
				StringBundler.concat(
					"Unable to parse tokens response from ", uri, ": ",
					parseException.getMessage()),
				parseException);
		}
	}

	private IDTokenClaimsSet _validate(
			ClientID clientID, Secret clientSecret, Nonce nonce,
			OIDCClientMetadata oidcClientMetadata,
			OIDCProviderMetadata oidcProviderMetadata, OIDCTokens oidcTokens)
		throws OpenIdConnectServiceException.TokenException {

		IDTokenValidator idTokenValidator = null;

		if (JWSAlgorithm.Family.HMAC_SHA.contains(
				oidcClientMetadata.getIDTokenJWSAlg())) {

			idTokenValidator = new IDTokenValidator(
				oidcProviderMetadata.getIssuer(), clientID,
				oidcClientMetadata.getIDTokenJWSAlg(), clientSecret);
		}
		else {
			URI uri = oidcProviderMetadata.getJWKSetURI();

			try {
				idTokenValidator = new IDTokenValidator(
					oidcProviderMetadata.getIssuer(), clientID,
					oidcClientMetadata.getIDTokenJWSAlg(), uri.toURL(),
					new DefaultResourceRetriever(1000, 1000));
			}
			catch (MalformedURLException malformedURLException) {
				throw new OpenIdConnectServiceException.TokenException(
					"Invalid JSON web key URL: " +
						malformedURLException.getMessage(),
					malformedURLException);
			}
		}

		try {
			return idTokenValidator.validate(oidcTokens.getIDToken(), nonce);
		}
		catch (BadJOSEException | JOSEException exception) {
			throw new OpenIdConnectServiceException.TokenException(
				StringBundler.concat(
					"Unable to validate tokens for client \"", clientID, "\": ",
					exception.getMessage()),
				exception);
		}
	}
	/*
	 * END: Copy methods from OpenIdConnectTokenRequestUtil
	 */

	/*
	 * BEGIN: Code from OpenIdConnectAuthenticationHandlerImpl
	 */
	@Override
	public void processAuthenticationResponse(
			HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			UnsafeConsumer<Long, Exception> userIdUnsafeConsumer)
		throws Exception {

		HttpSession httpSession = httpServletRequest.getSession();

		OpenIdConnectAuthenticationSession openIdConnectAuthenticationSession =
			(OpenIdConnectAuthenticationSession)httpSession.getAttribute(
				_OPEN_ID_CONNECT_AUTHENTICATION_SESSION);

		httpSession.removeAttribute(_OPEN_ID_CONNECT_AUTHENTICATION_SESSION);

		if (openIdConnectAuthenticationSession == null) {
			if (_log.isDebugEnabled()) {
				_log.debug(
					"OpenId Connect authentication was not requested or " +
						"removed");
			}

			return;
		}

		AuthenticationSuccessResponse authenticationSuccessResponse =
			_getAuthenticationSuccessResponse(httpServletRequest);

		_validateState(
			openIdConnectAuthenticationSession.getState(),
			authenticationSuccessResponse.getState());

		OAuthClientEntry oAuthClientEntry =
			_oAuthClientEntryLocalService.getOAuthClientEntry(
				openIdConnectAuthenticationSession.getOAuthClientEntryId());

		OIDCClientInformation oidcClientInformation =
			OIDCClientInformation.parse(
				JSONObjectUtils.parse(oAuthClientEntry.getInfoJSON()));

		OIDCProviderMetadata oidcProviderMetadata =
			_authorizationServerMetadataResolver.resolveOIDCProviderMetadata(
				oAuthClientEntry.getAuthServerWellKnownURI());

		// Replaced OpenIdConnectTokenRequestUtil call with private override
		OIDCTokens oidcTokens = request(
			authenticationSuccessResponse,
			openIdConnectAuthenticationSession.getNonce(),
			oidcClientInformation, oidcProviderMetadata,
			_getLoginRedirectURI(httpServletRequest),
			oAuthClientEntry.getTokenRequestParametersJSON());

		String userInfoJSON = _requestUserInfoJSON(
			oidcTokens.getAccessToken(), oidcProviderMetadata);

		long userId = _oidcUserInfoProcessor.processUserInfo(
			_portal.getCompanyId(httpServletRequest),
			String.valueOf(oidcProviderMetadata.getIssuer()),
			ServiceContextFactory.getInstance(httpServletRequest), userInfoJSON,
			oAuthClientEntry.getOIDCUserInfoMapperJSON());

		userIdUnsafeConsumer.accept(userId);

		httpSession = httpServletRequest.getSession();

		long openIdConnectSessionId =
			_offlineOpenIdConnectSessionManager.startOpenIdConnectSession(
				oAuthClientEntry.getAuthServerWellKnownURI(),
				String.valueOf(oidcClientInformation.getID()), oidcTokens,
				userId);

		httpSession.setAttribute(
			OpenIdConnectWebKeys.OPEN_ID_CONNECT_SESSION,
			new OpenIdConnectSessionImpl(
				openIdConnectSessionId,
				oAuthClientEntry.getAuthServerWellKnownURI(),
				openIdConnectAuthenticationSession.getNonce(),
				openIdConnectAuthenticationSession.getState(), userId));
		httpSession.setAttribute(
			OpenIdConnectWebKeys.OPEN_ID_CONNECT_SESSION_ID,
			openIdConnectSessionId);
	}

	@Override
	public void requestAuthentication(
			long oAuthClientEntryId, HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse)
		throws PortalException {

		HttpSession httpSession = httpServletRequest.getSession();

		Long openIdConnectSessionId = (Long)httpSession.getAttribute(
			OpenIdConnectWebKeys.OPEN_ID_CONNECT_SESSION_ID);

		if (openIdConnectSessionId != null) {
			httpSession.removeAttribute(
				OpenIdConnectWebKeys.OPEN_ID_CONNECT_SESSION_ID);
		}

		OAuthClientEntry oAuthClientEntry =
			_oAuthClientEntryLocalService.getOAuthClientEntry(
				oAuthClientEntryId);

		Map<String, Object> runtimeRequestParameters =
			HashMapBuilder.<String, Object>put(
				"nonce", new Nonce()
			).put(
				"redirect_uri", _getLoginRedirectURI(httpServletRequest)
			).put(
				"state", new State()
			).put(
				"ui_Locals", _getLangTags(httpServletRequest)
			).build();

		try {
			OIDCProviderMetadata oidcProviderMetadata =
				_authorizationServerMetadataResolver.
					resolveOIDCProviderMetadata(
						oAuthClientEntry.getAuthServerWellKnownURI());

			URI authenticationRequestURI = _getAuthenticationRequestURI(
				oidcProviderMetadata.getAuthorizationEndpointURI(),
				oAuthClientEntry.getAuthRequestParametersJSON(),
				oAuthClientEntry.getClientId(), runtimeRequestParameters);

			if (_log.isDebugEnabled()) {
				_log.debug(
					"Authentication request query: " +
						authenticationRequestURI.getQuery());
			}

			httpServletResponse.sendRedirect(
				authenticationRequestURI.toString());

			httpSession.setAttribute(
				_OPEN_ID_CONNECT_AUTHENTICATION_SESSION,
				new OpenIdConnectAuthenticationSession(
					(Nonce)runtimeRequestParameters.get("nonce"),
					oAuthClientEntryId,
					(State)runtimeRequestParameters.get("state")));
		}
		catch (Exception exception) {
			throw new PortalException(exception);
		}
	}

	@Override
	public void requestAuthentication(
			String openIdConnectProviderName,
			HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse)
		throws PortalException {

		requestAuthentication(
			_openIdConnectProviderManagedServiceFactory.getOAuthClientEntryId(
				_portal.getCompanyId(httpServletRequest),
				openIdConnectProviderName),
			httpServletRequest, httpServletResponse);
	}

	private URI _getAuthenticationRequestURI(
			URI authenticationEndpointURI,
			String authenticationRequestParametersJSON, String clientId,
			Map<String, Object> runtimeRequestParameters)
		throws Exception {

		JSONObject authenticationRequestParametersJSONObject =
			JSONObjectUtils.parse(authenticationRequestParametersJSON);

		AuthenticationRequest.Builder builder =
			new AuthenticationRequest.Builder(
				OpenIdConnectRequestParametersUtil.getResponseType(
					authenticationRequestParametersJSONObject),
				OpenIdConnectRequestParametersUtil.getScope(
					authenticationRequestParametersJSONObject),
				new ClientID(clientId),
				(URI)runtimeRequestParameters.get("redirect_uri"));

		builder = builder.endpointURI(
			authenticationEndpointURI
		).nonce(
			(Nonce)runtimeRequestParameters.get("nonce")
		).resources(
			OpenIdConnectRequestParametersUtil.getResourceURIs(
				authenticationRequestParametersJSONObject)
		).state(
			(State)runtimeRequestParameters.get("state")
		).uiLocales(
			(List<LangTag>)runtimeRequestParameters.get("ui_locales")
		);

		OpenIdConnectRequestParametersUtil.consumeCustomRequestParameters(
			builder::customParameter,
			authenticationRequestParametersJSONObject);

		return builder.build(
		).toURI();
	}

	private AuthenticationSuccessResponse _getAuthenticationSuccessResponse(
			HttpServletRequest httpServletRequest)
		throws OpenIdConnectServiceException.AuthenticationException {

		StringBuffer requestURL = httpServletRequest.getRequestURL();

		if (Validator.isNotNull(httpServletRequest.getQueryString())) {
			requestURL.append(StringPool.QUESTION);
			requestURL.append(httpServletRequest.getQueryString());
		}

		try {
			URI requestURI = new URI(requestURL.toString());

			AuthenticationResponse authenticationResponse =
				AuthenticationResponseParser.parse(requestURI);

			if (authenticationResponse instanceof AuthenticationErrorResponse) {
				AuthenticationErrorResponse authenticationErrorResponse =
					(AuthenticationErrorResponse)authenticationResponse;

				ErrorObject errorObject =
					authenticationErrorResponse.getErrorObject();

				JSONObject jsonObject = errorObject.toJSONObject();

				throw new OpenIdConnectServiceException.AuthenticationException(
					jsonObject.toString());
			}

			return (AuthenticationSuccessResponse)authenticationResponse;
		}
		catch (ParseException | URISyntaxException exception) {
			throw new OpenIdConnectServiceException.AuthenticationException(
				StringBundler.concat(
					"Unable to process response from ", requestURL.toString(),
					": ", exception.getMessage()),
				exception);
		}
	}

	private List<LangTag> _getLangTags(HttpServletRequest httpServletRequest) {
		Locale locale = _portal.getLocale(httpServletRequest);

		if (locale == null) {
			return null;
		}

		try {
			return Collections.singletonList(new LangTag(locale.getLanguage()));
		}
		catch (LangTagException langTagException) {
			if (_log.isDebugEnabled()) {
				_log.debug(
					"Unable to create a lang tag with locale " +
						locale.getLanguage(),
					langTagException);
			}

			return null;
		}
	}

	private URI _getLoginRedirectURI(HttpServletRequest httpServletRequest) {
		try {
			return new URI(
				StringBundler.concat(
					_portal.getPortalURL(httpServletRequest),
					_portal.getPathContext(),
					OpenIdConnectConstants.REDIRECT_URL_PATTERN));
		}
		catch (URISyntaxException uriSyntaxException) {
			throw new SystemException(
				"Unable to generate OpenId Connect login redirect URI: " +
					uriSyntaxException.getMessage(),
				uriSyntaxException);
		}
	}

	private String _requestUserInfoJSON(
			AccessToken accessToken, OIDCProviderMetadata oidcProviderMetadata)
		throws OpenIdConnectServiceException.UserInfoException {

		UserInfoRequest userInfoRequest = new UserInfoRequest(
			oidcProviderMetadata.getUserInfoEndpointURI(),
			(BearerAccessToken)accessToken);

		HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();

		httpRequest.setAccept(
			"text/html, image/gif, image/jpeg, */*; q=0.2, */*; q=0.2");

		try {
			HTTPResponse httpResponse = httpRequest.send();

			UserInfoResponse userInfoResponse = UserInfoResponse.parse(
				httpResponse);

			if (userInfoResponse instanceof UserInfoErrorResponse) {
				UserInfoErrorResponse userInfoErrorResponse =
					(UserInfoErrorResponse)userInfoResponse;

				ErrorObject errorObject =
					userInfoErrorResponse.getErrorObject();

				JSONObject jsonObject = errorObject.toJSONObject();

				throw new OpenIdConnectServiceException.UserInfoException(
					jsonObject.toString());
			}

			UserInfoSuccessResponse userInfoSuccessResponse =
				(UserInfoSuccessResponse)userInfoResponse;

			UserInfo userInfo = userInfoSuccessResponse.getUserInfo();

			if (userInfo == null) {
				JWT userInfoJWT = userInfoSuccessResponse.getUserInfoJWT();

				userInfo = new UserInfo(userInfoJWT.getJWTClaimsSet());
			}

			return userInfo.toJSONString();
		}
		catch (IOException ioException) {
			throw new OpenIdConnectServiceException.UserInfoException(
				StringBundler.concat(
					"Unable to get user information from ",
					oidcProviderMetadata.getUserInfoEndpointURI(), ": ",
					ioException.getMessage()),
				ioException);
		}
		catch (java.text.ParseException | ParseException exception) {
			throw new OpenIdConnectServiceException.UserInfoException(
				StringBundler.concat(
					"Unable to parse user information response from ",
					oidcProviderMetadata.getUserInfoEndpointURI(), ": ",
					exception.getMessage()),
				exception);
		}
	}

	private void _validateState(State requestedState, State state)
		throws Exception {

		if (!state.equals(requestedState)) {
			throw new OpenIdConnectServiceException.AuthenticationException(
				StringBundler.concat(
					"Requested value \"", requestedState.getValue(),
					"\" and approved state \"", state.getValue(),
					"\" do not match"));
		}
	}

	private static final String _OPEN_ID_CONNECT_AUTHENTICATION_SESSION =
		OpenIdConnectAuthenticationHandlerImpl.class.getName() +
			"#OPEN_ID_CONNECT_AUTHENTICATION_SESSION";

	@Reference
	private AuthorizationServerMetadataResolver
		_authorizationServerMetadataResolver;

	@Reference
	private OAuthClientEntryLocalService _oAuthClientEntryLocalService;

	@Reference
	private OfflineOpenIdConnectSessionManager
		_offlineOpenIdConnectSessionManager;

	@Reference
	private OIDCUserInfoProcessor _oidcUserInfoProcessor;

	@Reference
	private OpenIdConnectProviderManagedServiceFactory
		_openIdConnectProviderManagedServiceFactory;

	@Reference
	private Portal _portal;

	/*
	 * END: Code from OpenIdConnectAuthenticationHandlerImpl
	 */

}
