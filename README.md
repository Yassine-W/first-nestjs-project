# Notes nest.js

```bash
nest new my-nest-project
```

This command will watch your files, automatically recompiling and reloading the server:

```bash
npm run start:dev
```

```bash
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted
```

## Default behaviour

the response status code is always 200 by default, except for POST requests which are 201

## Lint error

```bash
'prettier/prettier': ['error', {endOfLine: 'auto'}]
```

## Creating controllers

```bash
nest g controller cats
```

## Creating services

```bash
nest g service cats
```

Service `@Injectable`

## Creating feature modules

```bash
nest g module cats
```

## Middleware

### Creation

#### Class way

```ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class PostMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    console.log('Post request...');
    next();
  }
}
```

#### Functional way

Consider using the simpler functional middleware alternative any time your middleware doesn't need any dependencies.

```ts
import { Request, Response, NextFunction } from 'express';

export function logger(req: Request, res: Response, next: NextFunction) {
  console.log(`Request...`);
  next();
}
```

### Use

There is no place for middleware in the `@Module()` decorator. Instead, we set them up using the `configure()` method of the module class. Modules that include middleware have to implement the `NestModule` interface.

#### Global Use

```ts
const app = await NestFactory.create(AppModule);
app.use(logger);
await app.listen(3000);
```

#### Specific Use

```ts
import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { CatsModule } from './cats/cats.module';
import { LoggerMiddleware } from './cats/logger.middleware';
import { PostMiddleware } from './cats/post.middleware';

@Module({
  imports: [CatsModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // consumer.apply(LoggerMiddleware).forRoutes('cats');
    consumer
      .apply(LoggerMiddleware)
      .exclude({ path: 'cats', method: RequestMethod.POST })
      .forRoutes({ path: 'cats', method: RequestMethod.ALL });
    consumer
      .apply(PostMiddleware)
      .forRoutes({ path: 'cats', method: RequestMethod.POST });
  }
}
```

## Exception

Nest comes with a built-in exceptions layer which is responsible for processing all unhandled exceptions across an application. When an exception is not handled by your application code, it is caught by this layer, which then automatically sends an appropriate user-friendly response.

Out of the box, this action is performed by a built-in global exception filter, which handles exceptions of type `HttpException` (and subclasses of it). When an exception is unrecognized (is neither HttpException nor a class that inherits from HttpException), the built-in exception filter generates the following default JSON response:

```json
{
  "statusCode": 500,
  "message": "Internal server error"
}
```

### Throw standard exception:

#### Example 1

```ts
@Get()
async findAll() {
  throw new HttpException
  (
    'Forbidden',
    HttpStatus.FORBIDDEN
  );
}
```

```json
{
  "statusCode": 403,
  "message": "Forbidden"
}
```

#### Example 2

```ts
@Get()
async findAll() {
  try {
    await this.service.findAll()
  } catch (err) {
    throw new HttpException(
        {
            status: HttpStatus.FORBIDDEN,
            error: 'This is a custom message',
        },
        HttpStatus.FORBIDDEN,
        {
            cause: err
        }
    );
  }
}
```

```json
{
  "status": 403,
  "error": "This is a custom message"
}
```

### Custom Exceptions

```ts
export class ForbiddenException extends HttpException {
  constructor() {
    super('Forbidden', HttpStatus.FORBIDDEN);
  }
}
////////////////////
throw new ForbiddenException();
```

### Built-in HTTP exceptions#

Nest provides a set of standard exceptions that inherit from the base HttpException. These are exposed from the `@nestjs/common` package, and represent many of the most common HTTP exceptions:

- BadRequestException
- UnauthorizedException
- NotFoundException
- ForbiddenException
- NotAcceptableException
- RequestTimeoutException
- ConflictException
- GoneException
- HttpVersionNotSupportedException
- PayloadTooLargeException
- UnsupportedMediaTypeException
- UnprocessableEntityException
- InternalServerErrorException
- NotImplementedException
- ImATeapotException
- MethodNotAllowedException
- BadGatewayException
- ServiceUnavailableException
- GatewayTimeoutException
- PreconditionFailedException

```ts
throw new BadRequestException('Something bad happened', {
  cause: new Error(),
  description: 'Some error description',
});
```

```json
{
  "message": "Something bad happened",
  "error": "Some error description",
  "statusCode": 400
}
```

### Exception filters

#### Creation

**_http-exception.filter.ts_**

```ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();

    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
```

#### Binding

Can take a single filter instance, or a comma-separated list of filter instances

Exception filters can be scoped at different levels:

##### method-scoped

**_cats.controller.ts_**

```ts
@Post()
@UseFilters(HttpExceptionFilter)
// Or
@UseFilters(new HttpExceptionFilter())
async create(@Body() createCatDto: CreateCatDto) {
  throw new ForbiddenException();
}
```

##### controller-scoped

**_cats.controller.ts_**

```ts
@UseFilters(new HttpExceptionFilter())
export class CatsController {}
```

##### global-scoped

**_main.ts_**

```ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalFilters(new HttpExceptionFilter());
  await app.listen(3000);
}
bootstrap();
```

Global-scoped filters are used across the whole application, for every controller and every route handler. In terms of dependency injection, global filters registered from outside of any module (with useGlobalFilters() as in the example above) cannot inject dependencies since this is done outside the context of any module. In order to solve this issue, you can register a global-scoped filter directly from any module using the following construction:

**_app.module.ts_**

```ts
import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';

@Module({
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class AppModule {}
```

### Catch anything filter

```ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    // In certain situations `httpAdapter` might not be available in the
    // constructor method, thus we should resolve it here.
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    const httpStatus =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const responseBody = {
      statusCode: httpStatus,
      timestamp: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(ctx.getRequest()),
    };

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
  }
}
```

When combining a filter that catches all exceptions "Catch anything" filter with a filter that is bound to a specific type, the "Catch anything" filter should be declared first. This is because the "Catch anything" filter will match any exception, and if it is declared after a more specific filter, it will catch all exceptions, including those that should be handled by the more specific filter.

```ts
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    // Handle all exceptions
  }
}

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    // Handle HttpExceptions
  }
}
```

then:

```ts
@Module({
  providers: [
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
})
export class AppModule {}
```

## Pipes

A pipe is a class annotated with the `@Injectable()` decorator, which implements the `PipeTransform` interface.

### Built-in pipes

Nest comes with nine pipes available out-of-the-box:

- ValidationPipe
- ParseIntPipe
- ParseFloatPipe
- ParseBoolPipe
- ParseArrayPipe
- ParseUUIDPipe
- ParseEnumPipe
- DefaultValuePipe
- ParseFilePipe

### Binding pipes

```ts
@Get(':id')
async findOne(@Param('id', ParseIntPipe) id: number) {
  return this.catsService.findOne(id);
}
```

in case of exception:

```json
{
  "statusCode": 400,
  "message": "Validation failed (numeric string is expected)",
  "error": "Bad Request"
}
```

### Class validator

```bash
npm i --save class-validator class-transformer
```

**_create-cat.dto.ts_**

```ts
import { IsString, IsInt } from 'class-validator';

export class CreateCatDto {
  @IsString()
  name: string;

  @IsInt()
  age: number;

  @IsString()
  breed: string;
}
```

Now we can create a ValidationPipe class that uses these annotations.

**_validation.pipe.ts_**

```ts
import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }
    const object = plainToInstance(metatype, value);
    const errors = await validate(object);
    if (errors.length > 0) {
      throw new BadRequestException('Validation failed');
    }
    return value;
  }

  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
```

#### Parameter Scoped Pipes

**_cats.controller.ts_**

```ts
@Post()
async create(
  @Body(new ValidationPipe()) createCatDto: CreateCatDto,
) {
  this.catsService.create(createCatDto);
}
```

#### Global Scoped Pipes

**_main.ts_**

```ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  await app.listen(3000);
}
bootstrap();
```

Note that in terms of dependency injection, global pipes registered from outside of any module (with useGlobalPipes() as in the example above) cannot inject dependencies since the binding has been done outside the context of any module. In order to solve this issue, you can set up a global pipe directly from any module using the following construction:

**_app.module.ts_**

```ts
import { Module } from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';

@Module({
  providers: [
    {
      provide: APP_PIPE,
      useClass: ValidationPipe,
    },
  ],
})
export class AppModule {}
```

## Guards

often referred to as `authorization`. Guards are executed **after** all middleware, but **before** any interceptor or pipe.

Like pipes and exception filters, guards can be `controller-scoped`, `method-scoped`, or `global-scoped`.

### Auth Guard

**_auth.guard.ts_**

```ts
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
```

### Role based Guard

**_roles.guard.ts_**

```ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    return true;
  }
}
```

#### Creating roles

**_roles.decorator.ts_**

```ts
import { SetMetadata } from '@nestjs/common';

export const Roles = (...roles: string[]) => SetMetadata('roles', roles);
```

#### Using roles

```ts
@Post()
@Roles('admin') // @SetMetadata('roles', ['admin'])
async create(@Body() createCatDto: CreateCatDto) {
  return this.catsService.create(createCatDto);
}
```

### Binding (Controller scoped)

```ts
@Controller('cats')
@UseGuards(RolesGuard)
export class CatsController {}
```

### Binding global

```ts
const app = await NestFactory.create(AppModule);
app.useGlobalGuards(new AuthGuard());
```

Global guards are used across the whole application, for every controller and every route handler. In terms of dependency injection, global guards registered from outside of any module (with useGlobalGuards() as in the example above) cannot inject dependencies since this is done outside the context of any module. In order to solve this issue, you can set up a guard directly from any module using the following construction:

**_app.module.ts_**

```ts
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

@Module({
  providers: [
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AppModule {}
```

Note that behind the scenes, when a guard returns false, the framework throws a ForbiddenException. If you want to return a different error response, you should throw your own specific exception. For example:

```ts
throw new UnauthorizedException();
```

```json
{
  "statusCode": 403,
  "message": "Forbidden resource",
  "error": "Forbidden"
}
```

## Interceptors

An interceptor is a class annotated with the `@Injectable()` decorator and implements the `NestInterceptor` interface.

They make it possible to:

- Bind extra logic before / after method execution
- Transform the result returned from a function
- Transform the exception thrown from a function
- Extend the basic function behavior
- Completely override a function depending on specific conditions (e.g., for caching purposes)

`Interceptors`, like `controllers`, `providers`, `guards`, and so on, can **inject dependencies** through their `constructor`

### RxJS

Methods I can use inside `pipe`:

- `tap`( callback )
- `map`( (data) => )
- `CatchError`( (err) => )

To create a new stream : `of()`

### Call Handler

The `CallHandler` interface implements the `handle()` method, which you can use to invoke the route handler method at some point in your interceptor.

The invocation of the route handler (i.e., calling handle()) is called a `Pointcut`, indicating that it's the point at which our additional logic is inserted.

### Logging Interceptor Example

In this example the `Befor...` text will be showed as soon as the interceptor is executed however the `After...` text will be showed only when the client recieve back the response from the server.

**_logging.interceptor.ts_**

```ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    console.log('Before...');

    const now = Date.now();
    return next.handle().pipe(
      tap(() => console.log(`After... ${Date.now() - now}ms`)),
      map((data) => ({ data })),
    );
  }
}
```

### Binding Interceptors

We use the `@UseInterceptors()` decorator. Like pipes and guards, interceptors can be:

- Controller-scoped

  **_cats.controller.ts_**

  ```ts
  @UseInterceptors(LoggingInterceptor)
  export class CatsController {}
  ```

- Method-scoped
- Global-scoped

  ```ts
  const app = await NestFactory.create(AppModule);
  app.useGlobalInterceptors(new LoggingInterceptor());
  ```

  Global interceptors are used across the whole application, for every controller and every route handler. In terms of dependency injection, global interceptors registered from outside of any module (with useGlobalInterceptors(), as in the example above) cannot inject dependencies since this is done outside the context of any module. In order to solve this issue, you can set up an interceptor directly from any module using the following construction:

  **_app.module.ts_**

  ```ts
  import { Module } from '@nestjs/common';
  import { APP_INTERCEPTOR } from '@nestjs/core';

  @Module({
    providers: [
      {
        provide: APP_INTERCEPTOR,
        useClass: LoggingInterceptor,
      },
    ],
  })
  export class AppModule {}
  ```

### Exception Mapping

Another interesting use-case is to take advantage of RxJS's `catchError()` operator to override thrown exceptions:

**_errors.interceptor.ts_**

```ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  BadGatewayException,
  CallHandler,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable()
export class ErrorsInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next
      .handle()
      .pipe(catchError((err) => throwError(() => new BadGatewayException())));
  }
}
```

When an exception is thrown, the Exception Filter will first attempt to handle the exception. If it cannot handle the exception, it will pass it on to the Exception Mapping Interceptor, which will attempt to map the exception to an appropriate response. If the Exception Mapping Interceptor also cannot handle the exception, it will be propagated further up the middleware chain to the global error handler.

### Stream overriding (Cache Interceptor)

**_cache.interceptor.ts_**

```ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable, of } from 'rxjs';

@Injectable()
export class CacheInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const isCached = true;
    if (isCached) {
      return of([]);
    }
    return next.handle();
  }
}
```

This CacheInterceptor has a hardcoded isCached variable and a hardcoded response [] as well. The key point to note is that we return a new stream here, created by the RxJS of() operator, therefore the route handler won't be called at all. When someone calls an endpoint that makes use of CacheInterceptor, the response (a hardcoded, empty array) will be returned immediately.

### Timeout Interceptor

After 5 seconds, request processing will be canceled:

**_timeout.interceptor.ts_**

```ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  RequestTimeoutException,
} from '@nestjs/common';
import { Observable, throwError, TimeoutError } from 'rxjs';
import { catchError, timeout } from 'rxjs/operators';

@Injectable()
export class TimeoutInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError) {
          return throwError(() => new RequestTimeoutException());
        }
        return throwError(() => err);
      }),
    );
  }
}
```

## Custom Route Decorators

An ES2016 decorator is an expression which returns a function and can take a target, name and property descriptor as arguments.

### Creating and Using Decorator

**_user.decorator.ts_**

```ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
```

then use it:

```ts
@Get()
async findOne(@User() user: UserEntity) {
  console.log(user);
}
```

### Decorators with Data

We can use this same decorator with different keys to access different properties. If the user object is deep or complex, this can make for easier and more readable request handler implementations.
**_user.decorator.ts_**

```ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const User = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);
```

Then use it:

```ts
@Get()
async findOne(@User('firstName') firstName: string) {
  console.log(`Hello ${firstName}`);
}
```

### Hints

- For TypeScript users, `createParamDecorator<T>()` is a generic. This means we can explicitly enforce type safety, for example `createParamDecorator<string>((data, ctx) => ...)`.

- Alternatively, specify a parameter type in the factory function, for example `createParamDecorator((data: string, ctx) => ...)`.

- If we omit both, the type for data will be any.

### Working with Pipes

Nest treats custom param decorators in the same fashion as the built-in ones (`@Body()`, `@Param()` and `@Query()`). This means that pipes are executed for the custom annotated parameters as well (in our examples, the user argument). Moreover, we can apply the pipe directly to the custom decorator.

The `validateCustomDecorators` option must be set to true. ValidationPipe does not validate arguments annotated with the custom decorators by default.

```ts
@Get()
async findOne(
  @User(new ValidationPipe({ validateCustomDecorators: true }))
  user: UserEntity,
) {
  console.log(user);
}
```

### Decorator Composition

Nest provides a helper method to compose multiple decorators. For example, suppose we want to combine all decorators related to authentication into a single decorator. This could be done with the following construction:

**_auth.decorator.ts_**

```ts
import { applyDecorators } from '@nestjs/common';

export function Auth(...roles: Role[]) {
  return applyDecorators(
    SetMetadata('roles', roles),
    UseGuards(AuthGuard, RolesGuard),
    ApiBearerAuth(),
    ApiUnauthorizedResponse({ description: 'Unauthorized' }),
  );
}
```

Then use it:

```ts
@Get('users')
@Auth('admin')
findAllUsers() {}
```

### Warning

The `@ApiHideProperty()` decorator from the `@nestjs/swagger` package is not composable and won't work properly with the applyDecorators function.
