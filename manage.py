#!/usr/bin/env python3
import os
import click
from flask.cli import FlaskGroup
from backend.app import create_app

# Set up CLI command group
@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """Management script for the domain analysis application"""
    pass

@cli.command("create-api-client")
@click.argument("name")
def create_api_client_command(name):
    """Generate new API client credentials"""
    from backend.utils.security import generate_api_client
    generate_api_client(name)

@cli.command("purge-rate-limits")
def purge_rate_limits_command():
    """Purge all rate limiting data"""
    from backend.utils.limiter import limiter
    limiter.storage.reset()
    click.echo("Rate limiting data purged.")

@cli.command("test-api-security")
@click.option("--api-key", help="API key to test")
@click.option("--client", help="Client name to test")
def test_api_security_command(api_key, client):
    """Test API security configuration"""
    app = create_app()
    
    with app.app_context():
        from backend.utils.security import api_security
        
        click.echo("API Security Configuration")
        click.echo("-----------------------")
        click.echo(f"Signing Required: {app.config.get('API_SIGNING_REQUIRED', False)}")
        click.echo(f"Signature TTL: {api_security.signature_ttl} seconds")
        click.echo(f"Number of API Keys: {len(api_security.api_keys)}")
        
        if api_key:
            if api_key in api_security.api_keys:
                client_info = api_security.api_keys[api_key]
                click.echo(f"\nAPI Key '{api_key[:8]}...' is valid")
                click.echo(f"Client: {client_info.get('name')}")
                click.echo(f"Client ID: {client_info.get('id')}")
                has_secret = 'secret_key' in client_info and client_info['secret_key']
                click.echo(f"Has Secret Key: {has_secret}")
            else:
                click.echo(f"\nAPI Key '{api_key[:8]}...' is NOT valid")
        
        if client:
            found = False
            for key, info in api_security.api_keys.items():
                if info.get('name') == client:
                    found = True
                    click.echo(f"\nClient '{client}' has API Key: {key[:8]}...")
            
            if not found:
                click.echo(f"\nNo API keys found for client '{client}'")
        
        click.echo("\nEnabled API Clients:")
        click.echo("--------------------")
        for key, info in api_security.api_keys.items():
            click.echo(f"- {info.get('name')} (key: {key[:8]}...)")

if __name__ == "__main__":
    cli()
