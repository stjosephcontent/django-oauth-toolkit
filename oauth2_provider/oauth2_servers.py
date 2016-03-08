import logging
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.oauth2.rfc6749.grant_types import (ResourceOwnerPasswordCredentialsGrant, AuthorizationCodeGrant,
                                                 ImplicitGrant, ClientCredentialsGrant, RefreshTokenGrant)
from oauthlib.oauth2.rfc6749.endpoints.authorization import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.endpoints.resource import ResourceEndpoint
from oauthlib.oauth2.rfc6749.endpoints.revocation import RevocationEndpoint
from oauthlib.oauth2.rfc6749 import errors

logger = logging.getLogger(__name__)


class MissingOrganizationIdError(errors.OAuth2Error):
    error = 'missing_organization'


class InvalidOrganizationError(errors.OAuth2Error):
    error = 'invalid_organization'


class OrgResourceOwnerPasswordCredentialsGrant(ResourceOwnerPasswordCredentialsGrant):

    def validate_token_request(self, request):

        super(OrgResourceOwnerPasswordCredentialsGrant, self).validate_token_request(request)

        if not getattr(request, 'organization_id', None):
            raise errors.InvalidRequestError(
                'Request is missing organization_id parameter.', request=request)

        if not self.request_validator.validate_organization(request.organization_id, request.user,
                                                            request.client, request):
            raise InvalidOrganizationError(
                'Invalid Organization given.', request=request)


class OrgAuthorizationCodeGrant(AuthorizationCodeGrant):

    def validate_authorization_request(self, request):
        scopes, credentials = super(OrgAuthorizationCodeGrant, self).validate_authorization_request(request)
        if getattr(request, 'organization_id', None):
            # organization_id is optional
            if not self.request_validator.validate_organization(request.organization_id, request.user,
                                                                request.client, request):
                raise InvalidOrganizationError(
                    'Invalid Organization given.', request=request
                )
            credentials['organization_id'] = request.organization_id

        return scopes, credentials


class OrgImplicitGrant(ImplicitGrant):

    def validate_authorization_request(self, request):
        scopes, credentials = super(OrgImplicitGrant, self).validate_authorization_request(request)
        if request.organization_id:
            # organization_id is optional
            if not self.request_validator.validate_organization(request.organization_id, request.user,
                                                                request.client, request):
                raise InvalidOrganizationError(
                    'Invalid Organization given.', request=request
                )
            credentials['organization_id'] = request.organization_id
        return scopes, credentials

    def validate_token_request(self, request):
        scopes, credentials = super(OrgImplicitGrant, self).validate_token_request(request)
        if request.organization_id:
            if not self.request_validator.validate_organization(request.organization_id, request.user,
                                                                request.client, request):
                raise InvalidOrganizationError(
                    'Invalid Organization given.', request=request)
            credentials['organization_id'] = request.organization_id

        return scopes, credentials


class OAuth2LibServer(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint, RevocationEndpoint):

    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        auth_grant = OrgAuthorizationCodeGrant(request_validator)
        implicit_grant = OrgImplicitGrant(request_validator)
        password_grant = OrgResourceOwnerPasswordCredentialsGrant(
            request_validator)
        credentials_grant = ClientCredentialsGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                             token_expires_in, refresh_token_generator)
        AuthorizationEndpoint.__init__(self, default_response_type='code',
                                       response_types={
                                           'code': auth_grant,
                                           'token': implicit_grant,
                                       },
                                       default_token_type=bearer)
        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                               grant_types={
                                   'authorization_code': auth_grant,
                                   'password': password_grant,
                                   'client_credentials': credentials_grant,
                                   'refresh_token': refresh_grant,
                               },
                               default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                                  token_types={'Bearer': bearer})
        RevocationEndpoint.__init__(self, request_validator)
