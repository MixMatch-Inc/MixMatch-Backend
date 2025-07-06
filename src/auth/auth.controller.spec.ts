import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AppleAuthService } from './apple/apple-auth.service';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

// Mock the dependencies
const mockAppleAuthService = {
  getMusicKitDeveloperToken: jest.fn(),
  validateSignInWithAppleCode: jest.fn(),
};

const mockUserRepository = {
  findOne: jest.fn(),
  create: jest.fn(),
  save: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn(),
};

const mockConfigService = {
  get: jest.fn(),
};

describe('AuthController', () => {
  let controller: AuthController;
  let appleAuthService: AppleAuthService;
  let usersRepository: Repository<User>;
  let jwtService: JwtService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AppleAuthService, useValue: mockAppleAuthService },
        { provide: getRepositoryToken(User), useValue: mockUserRepository },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    appleAuthService = module.get<AppleAuthService>(AppleAuthService);
    usersRepository = module.get<Repository<User>>(getRepositoryToken(User));
    jwtService = module.get<JwtService>(JwtService);

    // Reset mocks before each test
    jest.clearAllMocks();
  });

  describe('getDeveloperToken', () => {
    it('should return a developer token', async () => {
      const mockToken = 'test-developer-token';
      (
        mockAppleAuthService.getMusicKitDeveloperToken as jest.Mock
      ).mockResolvedValue(mockToken);

      const result = await controller.getDeveloperToken();
      expect(result).toEqual({ developerToken: mockToken });
      expect(
        mockAppleAuthService.getMusicKitDeveloperToken,
      ).toHaveBeenCalledTimes(1);
    });
  });

  describe('signInWithAppleCallback', () => {
    const mockCode = 'mock-auth-code';
    const mockAppleAuthData = {
      appleUserId: 'apple_user_id_123',
      email: 'user@example.com',
      appleRefreshToken: 'refresh_token_abc',
    };
    const mockUser = {
      id: 'uuid-123',
      appleUserId: 'apple_user_id_123',
      email: 'user@example.com',
      appleRefreshToken: 'refresh_token_abc',
    } as User;
    const mockResponse = {
      json: jest.fn(),
      status: jest.fn().mockReturnThis(),
    } as any;

    it('should create a new user and return auth token if user does not exist', async () => {
      (
        mockAppleAuthService.validateSignInWithAppleCode as jest.Mock
      ).mockResolvedValue(mockAppleAuthData);
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      (mockUserRepository.create as jest.Mock).mockReturnValue(mockUser);
      (mockUserRepository.save as jest.Mock).mockResolvedValue(mockUser);
      (mockJwtService.sign as jest.Mock).mockReturnValue('app-jwt-token');

      await controller.signInWithAppleCallback(
        {
          code: mockCode,
          user: {
            email: 'user@example.com',
            name: { firstName: 'John', lastName: 'Doe' },
          },
        },
        mockResponse,
      );

      expect(
        mockAppleAuthService.validateSignInWithAppleCode,
      ).toHaveBeenCalledWith(mockCode);
      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { appleUserId: 'apple_user_id_123' },
      });
      expect(mockUserRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          appleUserId: 'apple_user_id_123',
          email: 'user@example.com',
          firstName: 'John',
        }),
      );
      expect(mockUserRepository.save).toHaveBeenCalledWith(mockUser);
      expect(mockJwtService.sign).toHaveBeenCalledWith({
        userId: mockUser.id,
        appleUserId: mockUser.appleUserId,
        email: mockUser.email,
      });
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Login successful',
        user: mockUser,
        token: 'app-jwt-token',
      });
    });

    it('should log in existing user and return auth token', async () => {
      (
        mockAppleAuthService.validateSignInWithAppleCode as jest.Mock
      ).mockResolvedValue(mockAppleAuthData);
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(mockUser); // User already exists
      (mockUserRepository.save as jest.Mock).mockResolvedValue(mockUser);
      (mockJwtService.sign as jest.Mock).mockReturnValue('app-jwt-token');

      await controller.signInWithAppleCallback(
        { code: mockCode },
        mockResponse,
      );

      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { appleUserId: 'apple_user_id_123' },
      });
      expect(mockUserRepository.create).not.toHaveBeenCalled(); // Should not create new user
      expect(mockUserRepository.save).toHaveBeenCalledWith(mockUser); // Should save (even if no change, for consistency or update logic)
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Login successful',
        user: mockUser,
        token: 'app-jwt-token',
      });
    });

    it('should handle authentication failure and return 401', async () => {
      (
        mockAppleAuthService.validateSignInWithAppleCode as jest.Mock
      ).mockRejectedValue(new UnauthorizedException('Invalid code'));

      await controller.signInWithAppleCallback(
        { code: mockCode },
        mockResponse,
      );

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: 'Authentication failed',
        error: 'Invalid code',
      });
    });
  });

  describe('connectMusicAccount', () => {
    const mockMusicUserToken = 'mut_token_123';
    const mockStorefrontId = 'us';
    const mockUserId = 'uuid-123';
    const mockUserRequest = {
      user: { userId: mockUserId }, // Simulates req.user from your AuthGuard
    } as any;
    const existingUser = {
      id: mockUserId,
      appleUserId: 'apple_user_id_123',
      email: 'user@example.com',
      musicUserToken: null, // Initially not linked
    } as User;

    beforeEach(() => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(existingUser);
      (mockUserRepository.save as jest.Mock).mockResolvedValue(existingUser);
    });

    it('should link Apple Music account for a user', async () => {
      const result = await controller.connectMusicAccount(
        mockUserRequest,
        mockMusicUserToken,
        mockStorefrontId,
      );

      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { id: mockUserId },
      });
      expect(mockUserRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          musicUserToken: mockMusicUserToken,
          musicStorefrontId: mockStorefrontId,
        }),
      );
      expect(result).toEqual({
        message: 'Apple Music account linked successfully!',
      });
    });

    it('should throw UnauthorizedException if musicUserToken is missing', async () => {
      await expect(
        controller.connectMusicAccount(mockUserRequest, null, mockStorefrontId),
      ).rejects.toThrow(UnauthorizedException);
      expect(mockUserRepository.save).not.toHaveBeenCalled();
    });

    it('should throw UnauthorizedException if user is not found', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null); // User not found
      await expect(
        controller.connectMusicAccount(
          mockUserRequest,
          mockMusicUserToken,
          mockStorefrontId,
        ),
      ).rejects.toThrow(UnauthorizedException);
      expect(mockUserRepository.save).not.toHaveBeenCalled();
    });
  });

  describe('getMusicStatus', () => {
    const mockUserId = 'uuid-123';
    const mockUserRequest = {
      user: { userId: mockUserId },
    } as any;
    const linkedUser = {
      id: mockUserId,
      musicUserToken: 'linked_mut',
      musicStorefrontId: 'gb',
    } as User;
    const unlinkedUser = {
      id: mockUserId,
      musicUserToken: null,
    } as User;

    it('should return true and storefrontId if music is linked', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(linkedUser);
      const result = await controller.getMusicStatus(mockUserRequest);
      expect(result).toEqual({ isMusicKitLinked: true, storefrontId: 'gb' });
    });

    it('should return false if music is not linked', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(unlinkedUser);
      const result = await controller.getMusicStatus(mockUserRequest);
      expect(result).toEqual({
        isMusicKitLinked: false,
        storefrontId: undefined,
      });
    });

    it('should throw UnauthorizedException if user is not found', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      await expect(controller.getMusicStatus(mockUserRequest)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
