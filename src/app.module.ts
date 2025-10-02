import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaService } from '../prisma/prisma.service';

@Module({
  imports: [AuthModule, PrismaModule],
  controllers: [],
  providers: [PrismaService],
})
export class AppModule {}
