import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    console.log(user);
    return this.matchRoles(roles, user.roles);
  }

  matchRoles(requiredRoles: string[], userRoles: string[]): boolean {
    for (const role of requiredRoles) {
      if (userRoles.includes(role)) {
        return true;
      }
    }
    return false;
  }
}
