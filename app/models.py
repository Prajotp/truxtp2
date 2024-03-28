from django.contrib.auth.models import AbstractUser
from django.db import models


#role
class Role(models.Model):
    role_id = models.IntegerField()
    role_name = models.CharField(max_length=100)
    description = models.TextField()
   
    created_by = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.IntegerField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.role_name

#user model
class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, default='')  
    company_name = models.CharField(max_length=255, default='')
    role_name = models.CharField(max_length=100, default=None, null=True)
    profile_path = models.ImageField(upload_to='profile_path/', blank=True, null=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, default=None)
    username = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    first_name = None
    last_name = None
    is_active=None
    is_staff = None
    is_superuser = None
    last_login = None
    date_joined = None

    @property
    def groups(self):
        return Group.objects.none()

    @property
    def user_permissions(self):
        return Permission.objects.none()

    def __str__(self):
        return self.email

# Module
class Module(models.Model):
    account_id = models.IntegerField()
    
    module_name = models.CharField(max_length=255)
    description = models.TextField()
    active_status_id = models.IntegerField(default=1)
    created_by = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.IntegerField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.module_name

#userRole
class UserRole(models.Model):
    account_id = models.IntegerField()
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    valid_from = models.DateTimeField()
    valid_till = models.DateTimeField()
    active_status_id = models.IntegerField()
    created_by = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.IntegerField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.role.role_name}"

#permission
class Permission(models.Model):
    module = models.ForeignKey(Module, on_delete=models.CASCADE)
    permission_name = models.CharField(max_length=255)
    description = models.TextField()
    active_status_id = models.IntegerField()
    created_by = models.IntegerField()
    updated_by = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

#Active status model
class ActiveStatus(models.Model):
    active_status_id = models.AutoField(primary_key=True)
    account_id = models.IntegerField(blank=True, null=True)
    status = models.CharField(max_length=255, blank=False, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.status


#role permission
class RolePermissions(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    valid_from = models.DateField()
    valid_till = models.DateField()
    active_status = models.ForeignKey(ActiveStatus, on_delete=models.CASCADE, default=None)

    created_by = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.IntegerField()
    updated_at = models.DateTimeField(auto_now=True)

