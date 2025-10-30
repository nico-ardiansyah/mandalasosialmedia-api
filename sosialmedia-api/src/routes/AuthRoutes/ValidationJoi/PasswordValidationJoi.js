const joi = require("joi");

const newPasswordValidation = joi.object({
    password: joi.string()
        .trim()
        .required()
        .min(8)
        .max(15)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,15}$/)
        .messages({
            'string.empty': 'Password is required',
            'any.required': 'This field is required',
            'string.min': 'Password must be at least 8 character long',
            'string.max': 'Password must be at most 15 character long',
            'string.pattern.base': 'Password must at least 1 uppercase latter, 1 lowercase latter, 1 number, and 1 special character'
        }),
        
    confirmPassword: joi.string()
        .trim()
        .required()
        .valid(joi.ref('password'))
        .messages({
            'any.only': 'Confirm password must be the same as password',
            'string.empty': 'Confirm password is required',
            'any.required': 'This field is required'
        }),
        
});

module.exports = newPasswordValidation;