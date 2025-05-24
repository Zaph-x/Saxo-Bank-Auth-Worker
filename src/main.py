import json
import random
import string
import logging
import threading
from objects.saxo_config import SaxoConfig
import requests
from redis import StrictRedis
from auth_server import AuthServer, run_server
import argparse
from requests import Session
import time
import os
from threading import Timer

logger = logging.getLogger(__name__)
session = Session()
channel: str = "oauth_access_token"


class RepeatTimer(Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)


def generate_state(length=16):
    """Generate a random state string for OAuth2 authorization."""
    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for _ in range(length))


def get_signin_url(config: SaxoConfig, state: str):
    """Generate the URL for the user to sign in to Saxo Bank."""
    response = requests.get(
        config.authorization_endpoint,
        params={
            "response_type": "code",
            "client_id": config.app_key,
            "redirect_uri": config.redirect_urls[0],
            "state": state,
        },
    )

    response.raise_for_status()
    return response.url


def wait_for_code(timeout: int = 120):
    counter = 0
    if AuthServer.get_code() is None:
        logger.debug("Waiting for code...")
        while AuthServer.get_code() is None and counter < timeout:
            logger.debug(f"Waiting for code... {counter}")
            time.sleep(1)
            counter += 1
    if counter >= timeout:
        logger.error("Timeout waiting for code")
        exit(1)
    logger.debug("Code received")


def await_authetication(saxo_config: SaxoConfig, redis: StrictRedis, signin_url: str):
    auth_server = run_server(saxo_config, signin_url)
    thread = threading.Thread(target=wait_for_code)
    thread.start()
    thread.join()
    auth_server.stop()
    redis.set("oauth_code", str(AuthServer.get_code()))


def get_token(config: SaxoConfig, redis: StrictRedis):
    """Exchange the authorization code for an access token."""
    response = requests.post(
        config.token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": redis.get("oauth_code"),
            "client_id": config.app_key,
            "client_secret": config.app_secret,
            "redirect_uri": config.redirect_urls[0],
        },
    )
    response.raise_for_status()
    return response.json()


def _refresh_token(redis: StrictRedis, config: SaxoConfig) -> dict:
    """Refresh the access token using the refresh token."""
    refresh_token = redis.get("oauth_refresh_token")
    response = requests.post(
        config.token_endpoint,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "redirect_uri": config.redirect_urls[0],
            "client_id": config.app_key,
            "client_secret": config.app_secret,
        },
    )
    response.raise_for_status()
    logger.debug("Token refreshed")
    token_data = response.json()
    store_token_data(redis, token_data)
    session.headers.update({"Authorization": f"Bearer {token_data['access_token']}"})
    return response.json()


def _periodic_refresh(interval: int, redis: StrictRedis, config: SaxoConfig) -> None:
    logger.debug("Refreshing token")
    token_data = _refresh_token(redis, config)
    threading.Timer(
        interval, _periodic_refresh, [token_data["expires_in"] - 30, redis, config]
    ).start()


def create_and_start_refresh_thread(
    redis: StrictRedis, config: SaxoConfig, token_data: dict
) -> None:
    """This method creates a thread to refresh the token periodically.
    It should be called after the user is authenticated.

    Args:
        token_data (TokenDataModel): The token data model object

    Example:
        >>> saxo_client.create_and_start_refresh_thread(token_data)
    """
    if token_data != {}:
        redis.set("oauth_access_token", token_data["access_token"])

    logger.debug("Starting timer for " + str(token_data["expires_in"]) + " seconds")
    refresh_thread = RepeatTimer(
        token_data["expires_in"] / 2, _refresh_token, [redis, config]
    )
    refresh_thread.start()


def store_token_data(redis: StrictRedis, token_data: dict) -> None:
    """Store the token data in Redis."""
    redis.set("oauth_access_token", token_data["access_token"])
    redis.publish(channel, token_data["access_token"])
    logger.debug("Access token stored in StrictRedis in channel " + channel)
    redis.set("oauth_refresh_token", token_data["refresh_token"])
    expiration_time = time.time() + token_data["expires_in"]
    redis.set("oauth_expiration_time", expiration_time)
    logger.debug("Token data stored in StrictRedis")


def main():
    args = argparse.ArgumentParser(
        description="Saxo Bank OAuth2 Authorization Code Flow"
    )
    args.add_argument(
        "--redis-host",
        type=str,
        default=os.environ.get("REDIS_HOST", "localhost"),
        help="Redis host",
    )
    args.add_argument(
        "--redis-port",
        type=int,
        default=os.environ.get("REDIS_PORT", 6379),
        help="Redis port",
    )
    args.add_argument(
        "--redis-db",
        type=int,
        default=os.environ.get("REDIS_DB", 0),
        help="Redis database number",
    )
    args.add_argument(
        "--config-file",
        type=str,
        default="saxoapp.json",
        help="Path to the configuration file",
    )
    args.add_argument(
        "--log-level",
        type=str,
        default=(os.environ.get("LOGLEVEL", "INFO")).upper(),
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )

    args = args.parse_args()
    logging.basicConfig(level=args.log_level)
    logger.debug("Starting Saxo Bank OAuth2 Authorization Code Flow")
    logger.debug(
        f"Using Redis at {args.redis_host}:{args.redis_port}, DB {args.redis_db}"
    )
    redis = StrictRedis(
        host=args.redis_host,
        port=args.redis_port,
        db=args.redis_db,
        charset="utf-8",
        decode_responses=True,
    )
    with open(args.config_file) as json_file:
        config = SaxoConfig.from_json(json.load(json_file))
        logger.debug("Loaded config")

    state = generate_state()
    redis.set("oauth_state", state)
    logger.debug("Generated state and stored")
    token_data = {}
    if redis.get("oauth_expiration_time") is None or time.time() > float(
        str(redis.get("oauth_expiration_time"))
    ):
        logger.debug("Token expired or not found, requesting new token")
        await_authetication(config, redis, get_signin_url(config, state))
        token_data = get_token(config, redis)
        store_token_data(redis, token_data)
    if redis.get("oauth_code") is None:
        logger.error("No code found in Redis, exiting")
        exit(1)
    if token_data == {} and redis.get("oauth_access_token") is None:
        logger.error("No token data found, exiting")
        exit(1)
    if token_data == {}:
        token_data = {
            "access_token": redis.get("oauth_access_token"),
            "refresh_token": redis.get("oauth_refresh_token"),
            "expires_in": float(redis.get("oauth_expiration_time"))
            - float(time.time()),  # type: ignore
        }
    logger.debug("Token received")
    store_token_data(redis, token_data)
    session.headers.update({"Authorization": f"Bearer {token_data['access_token']}"})
    create_and_start_refresh_thread(redis, config, token_data)


if __name__ == "__main__":
    main()
