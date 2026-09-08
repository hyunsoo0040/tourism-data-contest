"""Rights-bound deterministic image analysis primitives."""

from itda.analysis.image.preprocessing import (
    DEFAULT_IMAGE_PREPROCESSING_POLICY,
    IMAGE_PREPROCESSING_FAILURE_REASON,
    IMAGE_PREPROCESSING_POLICY_VERSION,
    ImagePreprocessingCandidate,
    ImagePreprocessingPolicy,
    ImagePreprocessingResult,
    ImageProjection,
    preprocess_image,
)
from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    FileIdentity,
    RightsBoundImage,
    SecureImageReadError,
    SecureReadPolicy,
    read_approved_image,
)

__all__ = [
    "ApprovedImageMaterialization",
    "DEFAULT_IMAGE_PREPROCESSING_POLICY",
    "FileIdentity",
    "IMAGE_PREPROCESSING_FAILURE_REASON",
    "IMAGE_PREPROCESSING_POLICY_VERSION",
    "ImagePreprocessingCandidate",
    "ImagePreprocessingPolicy",
    "ImagePreprocessingResult",
    "ImageProjection",
    "RightsBoundImage",
    "SecureImageReadError",
    "SecureReadPolicy",
    "preprocess_image",
    "read_approved_image",
]
