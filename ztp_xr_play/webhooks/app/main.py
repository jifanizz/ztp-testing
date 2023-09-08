import logging
from typing import Union
from fastapi import FastAPI, Header
from pydantic import BaseModel

api = FastAPI()
logger = logging.getLogger(__name__)


class WebhookPayload(BaseModel):
    serialNo: str


class WebhookResponse(BaseModel):
    message: str


@api.post("/bpa/api/v2.0/device-activation/activate-device/")
async def notify(info: WebhookPayload,
                 authorization: Union[str, None] = Header(default=None),
                 apikey: Union[str, None] = Header(default=None)) -> WebhookResponse:
    logger.info(f"Notification: serialNo: {info.serialNo}, headers: apiKey: {apikey}, authorization: {authorization}")

    return WebhookResponse(message="Notification processed successfully")


logger.info("Ready to receive notifications")
