from django.forms import ValidationError
from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.forms import PasswordResetForm
from .models import *
from django.contrib.auth import get_user_model, authenticate

UserModel = get_user_model

class UserRegisterSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserModel
		fields = '__all__'
        
	def create(self, clean_data):
		user_obj = UserModel.objects.create_user(email=clean_data['email'], password=clean_data['password'])
		user_obj.username = clean_data['username']
		user_obj.save()
		return user_obj


class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'role']

    def create(self, validated_data):
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            role=validated_data['role']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.role = validated_data.get('role', instance.role)
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance


class UserLoginSerializer(serializers.Serializer):

    class Meta:
        model = CustomUser
        fields = '__all__'

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            raise serializers.ValidationError('Invalid login credentials')
        
        if not user.check_password(password):
            raise serializers.ValidationError('Invalid login credentials')
        
        return user

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model: CustomUser
        fields = '__all__'
    
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        self.reset_form = PasswordResetForm(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(('Error validating email'))
        return value

    def save(self):
        request = self.context.get('request')
        self.reset_form.save(
            use_https=request.is_secure(),
            email_template_name='registration/password_reset_email.html',
            request=request,
        )

# events/serializers.py

class EventsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Events
        fields = '__all__'

class TicketsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tickets
        fields = '__all__'

class VendorsSerializer(serializers.ModelSerializer):

    class Meta:
        model = Vendors
        fields = '__all__'
class ContactsSerializer(serializers.ModelSerializer):

    class Meta:
        model = Contacts
        fields = '__all__'

