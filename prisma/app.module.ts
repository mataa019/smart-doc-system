import { Module } from '@nestjs/common';
import { AuthModule } from '../src/auth/auth.module';
import { PrismaService } from './prisma.service';

@Module({
  imports: [AuthModule, PrismaModule],
  controllers: [],
  providers: [PrismaService],
})
export class AppModule {}
