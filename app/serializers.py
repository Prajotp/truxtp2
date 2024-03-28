from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import CustomUser

from django.contrib.auth.hashers import make_password
from .models import Role,UserRole
from .models import Module,Permission,RolePermissions,ActiveStatus


class ModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Module
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        
        fields = '__all__'
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))

       
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        if not any(char.islower() for char in value):
            raise serializers.ValidationError('Password must contain at least one lowercase letter.')
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError('Password must contain at least one digit.')
        if not any(not char.isalnum() for char in value):
            raise serializers.ValidationError('Password must contain at least one special character.')

        return value
    def update(self, instance, validated_data):
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])
        return super(UserSerializer, self).update(instance, validated_data)

    def create(self, validated_data):
        role_name = validated_data.pop('role_name', None)  # Remove 'role_name' if it exists
        role_id = validated_data.pop('role_id', None)  # Remove 'role_id' if it exists
        if not role_id and role_name:
            role = Role.objects.get(role_name=role_name)  # Fetch the Role instance based on role_name
        elif role_id:
            role = Role.objects.get(pk=role_id)  # Fetch the Role instance based on role_id
        else:
            role = None

        user = CustomUser(
            email=validated_data['email'],
            full_name=validated_data.get('full_name', ''),
            company_name=validated_data.get('company_name', ''),
            role=role,  # Assign the fetched Role instance to the 'role' field
            role_name=role_name,  # Assign role_name
            profile_path=validated_data.get('profile_path', None),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)
        return {'id': data['id'], 'role_name': data['role_name']}

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = '__all__'

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = '__all__'

class RolePermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolePermissions
        fields = '__all__'



class ActiveStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActiveStatus
        fields = '__all__'