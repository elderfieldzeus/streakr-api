const env = {
    JWT_SECRET: process.env.JWT_SECRET || 'your_jwt_secret',
    PORT: parseInt(process.env.PORT || '3000', 10),
}

export default env;