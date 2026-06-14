import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';

export const validate = (schema: AnyZodObject) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const parsed = await schema.parseAsync({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      // Replace request parts with validated and parsed data (coerces types, handles defaults)
      req.body = parsed.body;
      req.query = parsed.query;
      req.params = parsed.params;
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        res.status(400).json({
          status: 'fail',
          errors: error.errors.map((err) => ({
            path: err.path.slice(1).join('.'), // Remove 'body', 'query', or 'params' prefix
            message: err.message,
          })),
        });
        return;
      }
      res.status(500).json({
        status: 'error',
        message: 'Internal server error during validation',
      });
    }
  };
};
