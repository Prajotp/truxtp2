from rest_framework import status
from rest_framework.response import Response
from .serializers import UserSerializer, UserRoleSerializer, RoleSerializer, ModuleSerializer,PermissionSerializer,RolePermissionsSerializer,ActiveStatusSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import RoleSerializer
from rest_framework import generics
from django.utils import timezone
from .models import UserRole, Role,Module,Permission,CustomUser,RolePermissions,ActiveStatus
from rest_framework.views import APIView
from django.db import IntegrityError
#register_user function
@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
        email = request.data.get('email')  # Change 'username' to 'email'
        password = request.data.get('password')

        user = None
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            pass

        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.check_password(password):
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    if request.method == 'POST':
        try:
            
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Create ,retrive,update,delete user
class CustomUserListCreate(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer

class CustomUserRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    
#modules
@api_view(['POST'])
def add_module(request):
    new_module = Module(
        account_id=request.data.get('account_id'),
        module_name=request.data.get('module_name'),
        description=request.data.get('description'),
        active_status_id=request.data.get('active_status_id'),
        created_by=request.data.get('created_by')
    )
    new_module.save()

    return Response({
        'success': True,
        'message': 'Module has been added successfully'
    })

@api_view(['GET'])
def fetch_all_modules(request):
    account_id = request.GET.get('account_id')
    modules = Module.objects.filter(account_id=account_id)
    serializer = ModuleSerializer(modules, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def fetch_single_module(request):
    account_id = request.GET.get('account_id')
    module_id = request.GET.get('module_id')
    module = Module.objects.filter(account_id=account_id, id=module_id).first()

    serializer = ModuleSerializer(module)
    return Response(serializer.data)

@api_view(['PUT'])
def update_module(request):
    account_id = request.data.get('account_id')
    module_id = request.data.get('module_id')
    module = Module.objects.filter(account_id=account_id, id=module_id).first()

    if module:
        module.module_name = request.data.get('module_name', module.module_name)
        module.description = request.data.get('description', module.description)
        module.active_status_id = request.data.get('active_status_id', module.active_status_id)
        module.updated_by = request.data.get('updated_by', module.updated_by)
        module.updated_at = timezone.now()
        module.save()
        return Response({
            'success': True,
            'message': 'Module has been updated successfully'
        })
    else:
        return Response({
            'success': False,
            'message': 'No record found'
        })


@api_view(['DELETE'])
def delete_module(request):
    module_id = request.data.get('id')
    if module_id is None:
        return Response({'error': 'Module ID is required'}, status=400)

    try:
        module = Module.objects.get(id=module_id)
    except Module.DoesNotExist:
        return Response({'error': 'Module not found'}, status=404)

    module.delete()
    return Response({'success': True, 'message': 'Module deleted successfully'}, status=200)


#roles
@api_view(['POST'])
def add_role(request):
    serializer = RoleSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'success': True, 'message': 'Role added successfully'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def fetch_roles_dropdown(request):
    roles = Role.objects.exclude(id__in=[1, 2])
    serializer = RoleSerializer(roles, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def fetch_single_role(request, role_id):
    role = Role.objects.get(pk=role_id)
    serializer = RoleSerializer(role)
    return Response(serializer.data)

@api_view(['PUT'])
def update_role(request, role_id):
    role = Role.objects.get(pk=role_id)
    serializer = RoleSerializer(instance=role, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'success': True, 'message': 'Role updated successfully'})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def delete_role(request, role_id):
    role = Role.objects.get(pk=role_id)
    role.delete()
    return Response({'success': True, 'message': 'Role deleted successfully'})



#userrole
class AssignRoleToUser(APIView):
    def post(self, request, format=None):
        serializer = UserRoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FetchAllUserRoles(APIView):
    def get(self, request, format=None):
        user_roles = UserRole.objects.all()
        serializer = UserRoleSerializer(user_roles, many=True)
        return Response(serializer.data)

class FetchAssignedRoleToSingleUser(APIView):
    def get(self, request, format=None):
        user_id = request.query_params.get('user_id')
        user_roles = UserRole.objects.filter(user_id=user_id)
        serializer = UserRoleSerializer(user_roles, many=True)
        return Response(serializer.data)

class UpdateAssignedRole(APIView):
    def put(self, request, format=None):
        user_role_id = request.data.get('user_role_id')
        try:
            user_role = UserRole.objects.get(pk=user_role_id)
        except UserRole.DoesNotExist:
            return Response({'error': 'User role not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserRoleSerializer(user_role, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteAssignedRole(APIView):
    def delete(self, request, format=None):
        user_role_id = request.query_params.get('user_role_id')
        try:
            user_role = UserRole.objects.get(pk=user_role_id)
        except UserRole.DoesNotExist:
            return Response({'error': 'User role not found'}, status=status.HTTP_404_NOT_FOUND)
        
        user_role.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

#permission

@api_view(['POST'])
def add_permission(request):
    serializer = PermissionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({'success': True, 'message': 'Permission was added successfully!'})
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def fetch_all_permissions(request):
    permissions = Permission.objects.all()
    serializer = PermissionSerializer(permissions, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def fetch_all_permissions_per_account(request):
    account_id = request.query_params.get('account_id')
    modules = Module.objects.filter(account_id=account_id)
    module_ids = modules.values_list('id', flat=True)
    permissions = Permission.objects.filter(module_id__in=module_ids)
    serializer = PermissionSerializer(permissions, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def fetch_permissions_per_module(request):
    module_id = request.query_params.get('module_id')
    module = Module.objects.get(id=module_id)
    module_name = module.module_name
    permissions = Permission.objects.filter(module=module)
    permission_names = [permission.permission_name for permission in permissions]
    result = {
        'module_name': module_name,
        'permissions': permission_names
    }
    return Response({
        'success': True,
        'data': result
    })

@api_view(['GET'])
def fetch_single_permission(request):
    permission_id = request.query_params.get('permission_id')
    permission = Permission.objects.get(id=permission_id)
    serializer = PermissionSerializer(permission)
    return Response(serializer.data)

@api_view(['PUT'])
def update_permission(request):
    permission_id = request.data.get('permission_id')
    permission = Permission.objects.get(id=permission_id)
    serializer = PermissionSerializer(permission, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'success': True,
            'message': 'Updated successfully!'
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def delete_permission(request):
    permission_id = request.data.get('permission_id')
    permission = Permission.objects.get(id=permission_id)
    permission.delete()
    return Response({
        'success': True,
        'message': 'Deleted successfully'
    })



@api_view(['POST'])
def assign_permissions_to_role(request):
    permissions = request.data.get('permissions', [])
    role_id = request.data.get('role_id')
    success_count = 0

    for permission_id in permissions:
        try:
            role_permission = RolePermissions.objects.create(
                role_id=role_id,
                permission_id=permission_id,
                valid_from=request.data.get('valid_from'),
                valid_till=request.data.get('valid_till'),
                active_status_id=request.data.get('active_status_id'),
                created_by=request.data.get('created_by')
            )
            success_count += 1
        except IntegrityError as e:
            # Handle integrity error (e.g., duplicate key)
            pass
        except Exception as e:
            # Handle other exceptions
            pass

    if success_count == len(permissions):
        return Response({'success': True, 'message': 'Permissions have been assigned to the role successfully'})
    else:
        return Response({'success': False, 'message': 'Some permissions could not be assigned to the role'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def fetch_all_role_permissions(request):
    account_id = request.query_params.get('account_id')
    role_permissions = RolePermissions.objects.filter(account_id=account_id).order_by('role_id')

    serializer = RolePermissionsSerializer(role_permissions, many=True)
    return Response(serializer.data)



