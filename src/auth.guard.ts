import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    return this.validateRequest(request);
  }

  private validateRequest(req: any): boolean {
    const token = req.headers.authorization;
    if (token !== 'MiMiCx1') {
      return false;
    }
    req.user = { name: 'Yassine', roles: ['admin', 'sup'] };
    return true;
  }
}
