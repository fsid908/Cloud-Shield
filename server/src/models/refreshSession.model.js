import mongoose from "mongoose";

const refreshSessionSchema = new mongoose.Schema(

    // refresh session user
    {
        userId:{
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true,
        },

        //identify all the rotated tokens family id 
        familyId: {
            type: mongoose.Schema.Types.UUID,
            required: true,
            index: true,
        },
        
        //hashed refresh token
        tokenHash: {
            type: String,
            required: true,
            unique: true,
        },

        //inactive timeout
        lastUsedAt: {
            type: Date,
            required: true,
        },

        //session expiration
        expiresAt: {
            type: Date,
            required: true,
            index: true,
        },

        //session not used again
        revokedAt: {
            type: Date,
            default: null,
        },

        // identify suspicious session
        userAgent: {
            type: String,
            default: null,
        },

        // for security monitoring
        ipAddress: {
            type: String,
            default: null,
        },

    },
    {
        timestamps: true,
    }
);

const RefreshSession = mongoose.model(
    "RefreshSession",
    refreshSessionSchema
);

export default RefreshSession;