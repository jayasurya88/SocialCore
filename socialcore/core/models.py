from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, unique=True, default='default_username')  # Add default value
    followers = models.ManyToManyField('self', symmetrical=False, related_name='following', blank=True)
    email = models.EmailField(max_length=191)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True, default='profile_pics/default_profile_pic.png')
    bio = models.TextField(blank=True, null=True)


    is_private = models.BooleanField(default=False)


    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self):
        return self.username

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()


from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    caption = models.TextField()
    image = models.ImageField(upload_to='post_images/', blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    likes = models.ManyToManyField(User, related_name='liked_posts', blank=True)

    def __str__(self):
        return self.caption[:50]  # Display the first 50 characters

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', null=True, blank=True, related_name='replies', on_delete=models.CASCADE)

    def __str__(self):
        return self.text[:50] 
    

from django.conf import settings
User = get_user_model()


class FriendRequest(models.Model):
    from_user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='sent_friend_requests', on_delete=models.CASCADE)
    to_user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='received_friend_requests', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.from_user} -> {self.to_user}"

class Friendship(models.Model):
    user1 = models.ForeignKey(User, related_name='friendship1', on_delete=models.CASCADE)
    user2 = models.ForeignKey(User, related_name='friendship2', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user1} is friends with {self.user2}"
    

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

def privacy_settings(request):
    user = request.user  # Get the currently logged-in user

    if request.method == 'POST':
        # Get the value of 'is_private' from the form, which will be 'on' if checked
        is_private = request.POST.get('is_private') == 'on'
        user.is_private = is_private  # Set the value for 'is_private'
        user.save()  # Save the updated privacy setting
        return redirect('profile')  # Redirect to the user's profile or any other page

    # Render the form with the current privacy setting
    return render(request, 'users/privacy_settings.html', {'is_private': user.is_private})






class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20)  # Adjust length if needed
    post = models.ForeignKey('Post', on_delete=models.CASCADE, null=True, blank=True)  # Optional if not related to a post
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_notifications', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        if self.notification_type == 'like':
            return f"{self.from_user.username} liked your post"
        elif self.notification_type == 'liked_you':
            return f"You liked {self.from_user.username}'s post"
        return super().__str__()
    









from django.utils import timezone
class Conversation(models.Model):
    participants = models.ManyToManyField(User, related_name='conversations')
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Conversation between {', '.join([user.username for user in self.participants.all()])}"

class Message(models.Model):
    conversation = models.ForeignKey(Conversation, related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    text = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Message from {self.sender.username} at {self.timestamp}"