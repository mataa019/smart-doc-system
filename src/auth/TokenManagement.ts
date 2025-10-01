import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { UserRole } from '@prisma/client';
import * as crypto from 'crypto';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class TokenManagementService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  /**
   * Generate both access and refresh tokens
   */
  async generateTokens(userId: string, email: string, role: UserRole): Promise<TokenPair> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { refreshTokenVersion: true },
    });

    const payload = { sub: userId, email, role };
    
    const accessToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_SECRET || 'secret',
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(
      { ...payload, version: user.refreshTokenVersion, type: 'refresh' },
      {
        secret: process.env.JWT_REFRESH_SECRET || 'refresh-secret',
        expiresIn: '7d',
      },
    );

    return { accessToken, refreshToken };
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string }> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET || 'refresh-secret',
      });

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token');
      }

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        select: { id: true, email: true, role: true, isActive: true, refreshTokenVersion: true },
      });

      if (!user?.isActive || user.refreshTokenVersion !== payload.version) {
        throw new UnauthorizedException('Invalid token');
      }

      const accessToken = this.jwtService.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
      }, {
        secret: process.env.JWT_SECRET || 'secret',
        expiresIn: '15m',
      });

      return { accessToken };
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Create session with cleanup
   */
  async createSession(userId: string, refreshToken: string, sessionData?: any): Promise<void> {
    // Clean expired sessions
    await this.prisma.userSession.deleteMany({
      where: { userId, expiresAt: { lt: new Date() } },
    });

    // Create new session
    await this.prisma.userSession.create({
      data: {
        sessionToken: crypto.randomBytes(16).toString('hex'),
        refreshToken,
        userId,
        deviceInfo: sessionData?.deviceInfo,
        ipAddress: sessionData?.ipAddress,
        userAgent: sessionData?.userAgent,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      },
    });
  }

  /**
   * Logout (invalidate sessions)
   */
  async logout(userId: string, sessionToken?: string): Promise<void> {
    const where = sessionToken 
      ? { userId, sessionToken, isActive: true }
      : { userId, isActive: true };

    await this.prisma.userSession.updateMany({
      where,
      data: { isActive: false },
    });
  }

  /**
   * Revoke all user tokens (security action)
   */
  async revokeAllTokens(userId: string): Promise<void> {
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: userId },
        data: { refreshTokenVersion: { increment: 1 } },
      }),
      this.prisma.userSession.updateMany({
        where: { userId, isActive: true },
        data: { isActive: false },
      }),
    ]);
  }

  /**
   * Validate access token
   */
  async validateToken(accessToken: string): Promise<any> {
    try {
      const payload = this.jwtService.verify(accessToken, {
        secret: process.env.JWT_SECRET || 'secret',
      });

      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        select: { id: true, email: true, role: true, isActive: true },
      });

      if (!user?.isActive) {
        throw new UnauthorizedException('User inactive');
      }

      return { userId: user.id, email: user.email, role: user.role };
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }
}