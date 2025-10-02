import { Injectable, UnauthorizedException, BadRequestException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { RegisterDto, LoginDto, AuthResponse } from './auth.dto';
import { UserRole } from '@prisma/client';
import { TokenManagementService } from './TokenManagement';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private tokenService: TokenManagementService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponse> {
    const { email, password, firstName, lastName, phone, departmentId, role } = registerDto;
    
    // Validate
    if (!this.isValidEmail(email)) {
      throw new BadRequestException('Invalid email format');
    }
    if (!this.isStrongPassword(password)) {
      throw new BadRequestException('Password must be at least 8 characters with uppercase, lowercase, and number');
    }

    // Check existing user
    const existingUser = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // Create user
    const user = await this.prisma.user.create({
      data: {
        email: email.toLowerCase(),
        passwordHash: await bcrypt.hash(password, 12),
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        phone: phone?.trim(),
        departmentId,
        role: role || UserRole.EMPLOYEE,
        emailVerificationToken: crypto.randomBytes(32).toString('hex'),
        emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
      include: { department: { select: { id: true, name: true } } },
    });

    

    // Send verification email
    await this.sendVerificationEmail(user.email, user.emailVerificationToken, user.firstName);
    const tokens = await this.tokenService.generateTokens(user.id, user.email, user.role);
    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        department: user.department,
      },
      ...tokens,
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponse> {
    const { email, password, deviceInfo, ipAddress, userAgent } = loginDto;

    // Find and validate user
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: { department: { select: { id: true, name: true } } },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check account lock
    if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
      throw new UnauthorizedException('Account locked');
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      await this.handleFailedLogin(user.id);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset login attempts and update
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        accountLockedUntil: null,
        lastLogin: new Date(),
      },
    });

    // Generate tokens and create session
    const tokens = await this.tokenService.generateTokens(user.id, user.email, user.role);
    await this.tokenService.createSession(user.id, tokens.refreshToken, {
      deviceInfo, ipAddress, userAgent,
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        department: user.department,
      },
      ...tokens,
    };
  }

  async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');

    const isValidOldPassword = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!isValidOldPassword) throw new UnauthorizedException('Current password incorrect');
    
    if (!this.isStrongPassword(newPassword)) {
      throw new BadRequestException('Password does not meet requirements');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash: await bcrypt.hash(newPassword, 12),
        lastPasswordChange: new Date(),
        refreshTokenVersion: { increment: 1 },
      },
    });

    await this.tokenService.revokeAllTokens(userId);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user) return; // Don't reveal if email exists

    const resetToken = crypto.randomBytes(32).toString('hex');
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: resetToken,
        passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000),
      },
    });

    await this.sendPasswordResetEmail(user.email, resetToken, user.firstName);
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetExpires: { gt: new Date() },
      },
    });

    if (!user) throw new BadRequestException('Invalid or expired token');
    if (!this.isStrongPassword(newPassword)) {
      throw new BadRequestException('Password does not meet requirements');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: await bcrypt.hash(newPassword, 12),
        passwordResetToken: null,
        passwordResetExpires: null,
        lastPasswordChange: new Date(),
        refreshTokenVersion: { increment: 1 },
      },
    });

    await this.tokenService.revokeAllTokens(user.id);
  }

  async verifyEmail(token: string): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: {
        emailVerificationToken: token,
        emailVerificationExpires: { gt: new Date() },
      },
    });

    if (!user) throw new BadRequestException('Invalid or expired token');

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isEmailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpires: null,
      },
    });
  }

  // Helper methods
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (user?.isActive && await bcrypt.compare(password, user.passwordHash)) {
      const { passwordHash, ...result } = user;
      return result;
    }
    return null;
  }

  private async handleFailedLogin(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    const attempts = (user?.failedLoginAttempts || 0) + 1;
    const lockUntil = attempts >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null;

    await this.prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: attempts, accountLockedUntil: lockUntil },
    });
  }

  private isValidEmail(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  private isStrongPassword(password: string): boolean {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/.test(password);
  }

  private async sendVerificationEmail(email: string, token: string, name: string): Promise<void> {
    console.log(`Verification email: ${email}, token: ${token}`);
    // TODO: Implement Outlook integration
  }

  private async sendPasswordResetEmail(email: string, token: string, name: string): Promise<void> {
    console.log(`Reset email: ${email}, token: ${token}`);
    // TODO: Implement Outlook integration

    await this.mailService.sendMail({
      to: email,
      subject: 'Password Reset',
      template: 'reset-password',
      context: {
        name,
        token,
      },
    });

  }
}