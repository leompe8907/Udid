from django.core.management.base import BaseCommand
from udid.models import AppCredentials
from udid.management.commands.keyGenerator import generate_rsa_key_pair

class Command(BaseCommand):
    help = 'Genera claves RSA para tipos de aplicación'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--app-type',
            type=str,
            help='Tipo de aplicación (android_tv, samsung_tv, lg_tv, set_top_box)'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Generar claves para todos los tipos de app'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Sobrescribir claves existentes'
        )
    
    def handle(self, *args, **options):
        app_types = [
            'android_tv', 'samsung_tv', 'lg_tv', 'set_top_box'
        ] if options['all'] else [options['app_type']]
        
        for app_type in app_types:
            if not app_type:
                continue
                
            # Verificar si ya existe
            existing = AppCredentials.objects.filter(
                app_type=app_type, 
                is_active=True
            ).first()
            
            if existing and not options['force']:
                self.stdout.write(
                    self.style.WARNING(f'Claves para {app_type} ya existen. Usa --force para sobrescribir.')
                )
                continue
            
            # Generar nuevas claves
            private_key, public_key = generate_rsa_key_pair()
            
            # Desactivar claves existentes si hay
            if existing:
                existing.is_active = False
                existing.save()
            
            # Crear nuevo registro
            app_creds = AppCredentials.objects.create(
                app_type=app_type,
                private_key_pem=private_key,
                public_key_pem=public_key,
                is_active=True
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'✅ Claves generadas para {app_type}')
            )
            
            # Mostrar clave pública para embeber
            self.stdout.write(f'\n📋 Clave pública para {app_type}:')
            self.stdout.write('=' * 50)
            self.stdout.write(public_key)
            self.stdout.write('=' * 50)