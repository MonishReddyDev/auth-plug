import Joi from "joi";

// Optional: Regex for strong passwords (at least one uppercase, one lowercase, one number, one special char)
const strongPassword = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$/;

export const registerSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } }) // disables TLD check for more flexibility
    .required()
    .messages({
      "string.email": "Email must be a valid email address.",
      "string.empty": "Email is required.",
      "any.required": "Email is required.",
    }),
  password: Joi.string().min(8).pattern(strongPassword).required().messages({
    "string.min": "Password must be at least 8 characters long.",
    "string.pattern.base":
      "Password must have at least one uppercase letter, one lowercase letter, one number, and one special character.",
    "string.empty": "Password is required.",
    "any.required": "Password is required.",
  }),
  role: Joi.string(),
});

export const loginSchema = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      "string.email": "Email must be a valid email address.",
      "string.empty": "Email is required.",
      "any.required": "Email is required.",
    }),
  password: Joi.string().required().messages({
    "string.empty": "Password is required.",
    "any.required": "Password is required.",
  }),
});
