const joi = require('joi');

const emailValidationJoi = joi.object({
    email: joi.string()
        .trim()
        .lowercase()
        .required()
        .email({ tlds: { allow: true }, minDomainSegments: 2 })
        .messages({
            'string.empty': 'Email is required',
            'any.required': 'This field is required',
            'string.email': 'Invalid email format',
        }),
});


module.exports = emailValidationJoi;