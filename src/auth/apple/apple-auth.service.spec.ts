import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AppleAuthService } from './apple-auth.service';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as appleSignin from 'apple-signin';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';

// Mock the external libraries
jest.mock('jsonwebtoken');
jest.mock('fs');
jest.mock('apple-signin');

describe('AppleAuthService', () => {
  let service: AppleAuthService;
  let configService: ConfigService;

  const mockMusicKitPrivateKey = 'MOCK_MUSICKIT_PRIVATE_KEY';
  const mockSignInPrivateKey = 'MOCK_SIGN_IN_PRIVATE_KEY';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AppleAuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              switch (key) {
                case 'app.apple.musicKitKeyId':
                  return 'MUSICKIT_KEY_ID';
                case 'app.apple.teamId':
                  return 'TEAM_ID';
                case 'app.apple.musicKitPrivateKeyPath':
                  return '/path/to/musickit.p8';
                case 'app.apple.signInClientId':
                  return 'SIGN_IN_CLIENT_ID';
                case 'app.apple.signInKeyId':
                  return 'SIGN_IN_KEY_ID';
                case 'app.apple.signInPrivateKeyPath':
                  return '/path/to/signin.p8';
                case 'app.apple.signInRedirectUri':
                  return 'https://your-domain.com/auth/apple/callback';
                default:
                  return null;
              }
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AppleAuthService>(AppleAuthService);
    configService = module.get<ConfigService>(ConfigService);

    // Reset mocks before each test
    (jwt.sign as jest.Mock).mockReset();
    (fs.readFileSync as jest.Mock).mockReset();
    (appleSignin.getClientSecret as jest.Mock).mockReset();
    (appleSignin.get.authorizationToken as jest.Mock).mockReset();
    (appleSignin.verifyIdToken as jest.Mock).mockReset();
    (appleSignin.get.refreshToken as jest.Mock).mockReset();

    // Mock fs.readFileSync to return the private keys
    (fs.readFileSync as jest.Mock).mockImplementation((path: string) => {
      if (path === '/path/to/musickit.p8') {
        return mockMusicKitPrivateKey;
      }
      if (path === '/path/to/signin.p8') {
        return mockSignInPrivateKey;
      }
      return ''; // Default for other paths
    });
  });

  afterEach(() => {
    jest.clearAllTimers(); // Clear timers set by scheduleDeveloperTokenRefresh
  });

  describe('getMusicKitDeveloperToken', () => {
    it('should generate and return a developer token', async () => {
      const mockToken = 'mock-developer-token';
      (jwt.sign as jest.Mock).mockReturnValue(mockToken);

      const token = await service.getMusicKitDeveloperToken();
      expect(token).toBe(mockToken);
      expect(fs.readFileSync).toHaveBeenCalledWith(
        '/path/to/musickit.p8',
        'utf8',
      );
      expect(jwt.sign).toHaveBeenCalledWith(
        {},
        mockMusicKitPrivateKey,
        expect.objectContaining({
          algorithm: 'ES256',
          issuer: 'TEAM_ID',
          header: { kid: 'MUSICKIT_KEY_ID' },
        }),
      );
    });

    it('should return cached token if not expired', async () => {
      const mockToken = 'cached-developer-token';
      // Manually set a cached token that's still valid
      (service as any).musicKitDeveloperToken = mockToken;
      (service as any).musicKitDeveloperTokenExpiry = new Date(
        Date.now() + 1000 * 60 * 60,
      ); // 1 hour from now

      const token = await service.getMusicKitDeveloperToken();
      expect(token).toBe(mockToken);
      expect(jwt.sign).not.toHaveBeenCalled(); // Should not regenerate
    });

    it('should regenerate token if cached token is expired', async () => {
      jest.useFakeTimers(); // Use fake timers to control Date.now()
      const mockOldToken = 'old-developer-token';
      const mockNewToken = 'new-developer-token';

      (service as any).musicKitDeveloperToken = mockOldToken;
      (service as any).musicKitDeveloperTokenExpiry = new Date(
        Date.now() - 1000,
      ); // 1 second ago

      (jwt.sign as jest.Mock).mockReturnValue(mockNewToken);

      const token = await service.getMusicKitDeveloperToken();
      expect(token).toBe(mockNewToken);
      expect(jwt.sign).toHaveBeenCalledTimes(1); // Should regenerate
    });

    it('should throw InternalServerErrorException if configuration is missing', async () => {
      (configService.get as jest.Mock).mockReturnValueOnce(null); // Simulate missing key ID

      await expect(service.getMusicKitDeveloperToken()).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw InternalServerErrorException if private key read fails', async () => {
      (fs.readFileSync as jest.Mock).mockImplementation(() => {
        throw new Error('File not found');
      });

      await expect(service.getMusicKitDeveloperToken()).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('validateSignInWithAppleCode', () => {
    const mockAuthCode = 'mock-auth-code';
    const mockClientSecret = 'mock-client-secret';
    const mockAppleResponse = {
      id_token: 'mock-id-token',
      refresh_token: 'mock-refresh-token',
      access_token: 'mock-access-token',
    };
    const mockDecodedIdToken = {
      sub: 'mock_apple_user_id',
      email: 'test@example.com',
      email_verified: true,
      is_private_email: false,
    };

    beforeEach(() => {
      (appleSignin.getClientSecret as jest.Mock).mockReturnValue(
        mockClientSecret,
      );
      (appleSignin.get.authorizationToken as jest.Mock).mockResolvedValue(
        mockAppleResponse,
      );
      (appleSignin.verifyIdToken as jest.Mock).mockResolvedValue(
        mockDecodedIdToken,
      );
    });

    it('should validate code and return user data', async () => {
      const result = await service.validateSignInWithAppleCode(mockAuthCode);

      expect(appleSignin.getClientSecret).toHaveBeenCalledTimes(1);
      expect(appleSignin.get.authorizationToken).toHaveBeenCalledWith(
        mockAuthCode,
        expect.objectContaining({
          clientID: 'SIGN_IN_CLIENT_ID',
          clientSecret: mockClientSecret,
          redirectUri: 'https://your-domain.com/auth/apple/callback',
        }),
      );
      expect(appleSignin.verifyIdToken).toHaveBeenCalledWith(
        mockAppleResponse.id_token,
        expect.any(Object),
      );
      expect(result).toEqual({
        appleUserId: 'mock_apple_user_id',
        email: 'test@example.com',
        emailVerified: true,
        isPrivateEmail: false,
        appleRefreshToken: 'mock-refresh-token',
      });
    });

    it('should throw UnauthorizedException if getClientSecret fails', async () => {
      (appleSignin.getClientSecret as jest.Mock).mockImplementation(() => {
        throw new Error('Secret error');
      });
      await expect(
        service.validateSignInWithAppleCode(mockAuthCode),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if authorization token cannot be obtained', async () => {
      (appleSignin.get.authorizationToken as jest.Mock).mockResolvedValue(null);
      await expect(
        service.validateSignInWithAppleCode(mockAuthCode),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if id_token verification fails', async () => {
      (appleSignin.verifyIdToken as jest.Mock).mockRejectedValue(
        new Error('Invalid ID token'),
      );
      await expect(
        service.validateSignInWithAppleCode(mockAuthCode),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('refreshSignInWithAppleToken', () => {
    const mockRefreshToken = 'old-refresh-token';
    const mockClientSecret = 'mock-client-secret-refresh';
    const mockAppleRefreshResponse = {
      access_token: 'new-access-token',
      refresh_token: 'potentially-new-refresh-token',
      id_token: 'new-id-token',
    };

    beforeEach(() => {
      (appleSignin.getClientSecret as jest.Mock).mockReturnValue(
        mockClientSecret,
      );
      (appleSignin.get.refreshToken as jest.Mock).mockResolvedValue(
        mockAppleRefreshResponse,
      );
    });

    it('should refresh token and return new tokens', async () => {
      const result =
        await service.refreshSignInWithAppleToken(mockRefreshToken);

      expect(appleSignin.getClientSecret).toHaveBeenCalledTimes(1);
      expect(appleSignin.get.refreshToken).toHaveBeenCalledWith(
        mockRefreshToken,
        expect.objectContaining({
          clientID: 'SIGN_IN_CLIENT_ID',
          clientSecret: mockClientSecret,
        }),
      );
      expect(result).toEqual({
        accessToken: 'new-access-token',
        refreshToken: 'potentially-new-refresh-token',
        idToken: 'new-id-token',
      });
    });

    it('should return original refresh token if Apple does not provide a new one', async () => {
      (appleSignin.get.refreshToken as jest.Mock).mockResolvedValue({
        access_token: 'new-access-token',
        id_token: 'new-id-token',
      }); // No refresh_token in response

      const result =
        await service.refreshSignInWithAppleToken(mockRefreshToken);
      expect(result.refreshToken).toBe(mockRefreshToken);
    });

    it('should throw UnauthorizedException if refresh token fails', async () => {
      (appleSignin.get.refreshToken as jest.Mock).mockResolvedValue(null);
      await expect(
        service.refreshSignInWithAppleToken(mockRefreshToken),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
