from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.conf import settings
from .models import CustomUser  # Import your custom user model
from django.contrib.auth import authenticate, login
from django.urls import reverse
from django.db.models import Q
# index page
# views.py
from django.shortcuts import render
from .models import Friendship, Post, Notification  # Import your models

def index(request):
    return render(request,'index.html')


def home(request):
    # Fetch all posts from users that the logged-in user follows
    following = Friendship.objects.filter(user1=request.user).values_list('user2', flat=True)
    posts = Post.objects.filter(user__in=following).order_by('-created_at')
    
    # Fetch the count of unread notifications
    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()

    context = {
        'posts': posts,
        'unread_notifications_count': unread_notifications_count,  # Add this line
    }
    return render(request, 'home.html', context)


def user_registration(request):
    return render(request,'user_registration.html')

def login_page(request):
    return render(request,'login.html')


User = get_user_model()
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone = request.POST.get('phone')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 == password2:
            # Ensure the username is unique
            if not CustomUser.objects.filter(username=username).exists():
                
                # Check if the email already has two accounts
                existing_accounts_email = CustomUser.objects.filter(email=email).count()
                if existing_accounts_email < 2:
                    # Check if the phone number already has two accounts
                    existing_accounts_phone = CustomUser.objects.filter(phone=phone).count()
                    if existing_accounts_phone < 2:
                        # Store user data temporarily in session
                        request.session['temp_user_data'] = {
                            'username': username,
                            'email': email,
                            'first_name': first_name,
                            'last_name': last_name,
                            'phone': phone,
                            'password': password1,  # Store password to set it later
                        }

                        # Generate OTP
                        otp = get_random_string(length=6, allowed_chars='0123456789')
                        request.session['otp'] = otp
                        request.session['otp_email'] = email
                        request.session['otp_phone'] = phone

                        # Send OTP via email
                        send_mail(
                            'Your OTP Code',
                            f'Your OTP code is {otp}. It is valid for 10 minutes.',
                            settings.DEFAULT_FROM_EMAIL,
                            [email],
                            fail_silently=False,
                        )

                        messages.success(request, 'Registration successful. Please check your email for the OTP code.')
                        return redirect('verify_otp')  # Redirect to OTP verification page
                    else:
                        messages.error(request, 'This phone number already has two accounts. Please use a different phone number.')
                else:
                    messages.error(request, 'This email already has two accounts. Please use a different email.')
            else:
                messages.error(request, 'Username is already in use. Please try a different one.')
        else:
            messages.error(request, 'Passwords do not match.')

    return render(request, 'user_registration.html')

def verify_otp(request):
    if request.method == 'POST':
        otp_code = request.POST.get('otp')

        # Retrieve OTP and email from session
        stored_otp = request.session.get('otp')
        stored_email = request.session.get('otp_email')
        stored_phone = request.session.get('otp_phone')

        if otp_code == stored_otp and stored_email:
            try:
                # Retrieve temporary user data from session
                temp_user_data = request.session.get('temp_user_data')

                if temp_user_data and temp_user_data['email'] == stored_email and temp_user_data['phone'] == stored_phone:
                    # Check the number of accounts with this email and phone number
                    existing_accounts_email = CustomUser.objects.filter(email=stored_email).count()
                    existing_accounts_phone = CustomUser.objects.filter(phone=stored_phone).count()

                    if existing_accounts_email < 2 and existing_accounts_phone < 2:
                        # Create user and save to database
                        user = CustomUser(
                            username=temp_user_data['username'],
                            email=temp_user_data['email'],
                            first_name=temp_user_data['first_name'],
                            last_name=temp_user_data['last_name'],
                            phone=temp_user_data['phone'],
                        )
                        user.set_password(temp_user_data['password'])
                        user.is_active = True  # Activate the user account
                        user.save()

                        # Clear OTP and temp user data from session
                        del request.session['otp']
                        del request.session['otp_email']
                        del request.session['otp_phone']
                        del request.session['temp_user_data']

                        messages.success(request, 'Your account has been activated. You can now log in.')
                        return redirect('login_page')
                    else:
                        messages.error(request, 'This email or phone number already has two accounts. Please use different credentials.')

                else:
                    messages.error(request, 'Invalid session data. Please try again.')

            except CustomUser.DoesNotExist:
                messages.error(request, 'User not found. Please try again.')
        else:
            messages.error(request, 'Invalid or expired OTP code.')

    return render(request, 'verification.html')






def login_view(request):
    if request.method == 'POST':
        identifier = request.POST.get('identifier')  # Can be email, phone, or username
        password = request.POST.get('password')

        # Retrieve all users matching the identifier (username, email, or phone)
        users = CustomUser.objects.filter(
            Q(username=identifier) | Q(email=identifier) | Q(phone=identifier)
        )

        if users.exists():
            # Loop through the users to find one with the correct password
            for user in users:
                if user.check_password(password):
                    user = authenticate(request, username=user.username, password=password)
                    if user is not None and user.is_active:
                        login(request, user)
                        
                        # Redirect based on user type (staff or regular user)
                        if user.is_staff:
                            messages.success(request, 'Staff login successful.')
                            return redirect('admin')  # Redirect to staff dashboard
                        else:
                            messages.success(request, 'Login successful.')
                            return redirect('my_profile_view', username=user.username)
            messages.error(request, 'Invalid credentials. Please try again.')
        else:
            messages.error(request, 'User not found. Please try again.')

    return render(request, 'login.html')

def admin(request):
    return render(request,'admin.html')


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')

        # Verify that the username is associated with the provided email
        try:
            user = CustomUser.objects.get(email=email, username=username)

            # Generate OTP
            otp = get_random_string(length=6, allowed_chars='0123456789')
            request.session['otp'] = otp
            request.session['email'] = email
            request.session['username'] = username

            # Send OTP via email
            send_mail(
                'Your Password Reset OTP',
                f'Your OTP code is {otp}. It is valid for 10 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            messages.success(request, 'OTP sent to your email.')
            return redirect('verify_reset_otp')

        except CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email and username.')
            return redirect('forgot_password')

    return render(request, 'forgot_password.html')

def verify_reset_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')

        # Retrieve OTP and email from session
        stored_otp = request.session.get('otp')
        email = request.session.get('email')
        username = request.session.get('username')

        if entered_otp == stored_otp:
            messages.success(request, 'OTP verified. You can now reset your password.')
            return redirect('reset_password')  # Redirect to password reset form
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'verify_otp.html')


def reset_password(request):
    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 == password2:
            email = request.session.get('email')
            username = request.session.get('username')

            # Retrieve the user by email and username
            try:
                user = CustomUser.objects.get(email=email, username=username)
                user.set_password(password1)
                user.save()

                # Clear session data
                del request.session['otp']
                del request.session['email']
                del request.session['username']

                messages.success(request, 'Password has been reset successfully. You can now log in.')
                return redirect('login_page')

            except CustomUser.DoesNotExist:
                messages.error(request, 'An error occurred. Please try again.')
        else:
            messages.error(request, 'Passwords do not match.')

    return render(request, 'reset_password.html')


from django.shortcuts import render, get_object_or_404
from .models import CustomUser

from django.shortcuts import render, get_object_or_404
from .models import CustomUser, FriendRequest
from django.shortcuts import render, get_object_or_404
from django.db.models import Q
from .models import CustomUser, Friendship, Post, FriendRequest

def profile_view(request, username):
    user_profile = get_object_or_404(CustomUser, username=username)
    is_own_profile = request.user == user_profile
    is_following = Friendship.objects.filter(user1=request.user, user2=user_profile).exists()
    is_followed_by_profile = Friendship.objects.filter(user1=user_profile, user2=request.user).exists()
    are_friends = is_following and is_followed_by_profile
    if is_own_profile:
        user_posts = Post.objects.filter(user=user_profile).order_by('-created_at')
    elif user_profile.is_private and not is_following:
        user_posts = []
    else:
        user_posts = Post.objects.filter(user=user_profile).order_by('-created_at')
    followers_count = Friendship.objects.filter(user2=user_profile).count()
    following_count = Friendship.objects.filter(user1=user_profile).count()
    friend_request_sent = FriendRequest.objects.filter(from_user=request.user, to_user=user_profile).exists()
    conversation = Conversation.objects.filter(participants=request.user).filter(participants=user_profile).first()
    conversation_id = conversation.id if conversation else None
    context = {
        'user': user_profile,
        'posts': user_posts,
        'followers_count': followers_count,
        'following_count': following_count,
        'are_friends': are_friends,
        'friend_request_sent': friend_request_sent,
        'conversation_id': conversation_id, 
          # Pass conversation_id to context
    }
    return render(request, 'profile.html', context)

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import CustomUser
import random
import string
def profile_update(request):
    user = request.user

    if request.method == 'POST':
        new_username = request.POST.get('username')
        new_name = request.POST.get('name')
        new_bio = request.POST.get('bio')    
        if 'profile_picture' in request.FILES:
            user.profile_picture = request.FILES['profile_picture']   
        if new_username and new_username != user.username:
            if CustomUser.objects.filter(username=new_username).exists():
                messages.error(request, 'Username is already taken.')
                return redirect('profile_update')
            else:
                user.username = new_username    
        user.first_name, user.last_name = new_name.split(' ', 1)
        user.bio = new_bio
        user.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('profile_view', username=user.username)
    suggested_usernames = get_suggested_usernames(user.username)
    return render(request, 'profile_update.html', {'user': user, 'suggested_usernames': suggested_usernames})
def get_suggested_usernames(current_username):
    """Generate a list of suggested usernames."""
    suggested_usernames = []
    for _ in range(5): 
        suggestion = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        if not CustomUser.objects.filter(username=suggestion).exists() and suggestion != current_username:
            suggested_usernames.append(suggestion)
    return suggested_usernames
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Post, Comment
from django.contrib.auth import get_user_model
User = get_user_model()
@login_required
def create_post(request):
    if request.method == 'POST':
        caption = request.POST.get('caption')
        location = request.POST.get('location')
        image = request.FILES.get('image')

        post = Post(user=request.user, caption=caption, location=location, image=image)
        post.save()
        
        messages.success(request, 'Post created successfully!')
        return redirect('profile_view', username=request.user.username)
    return render(request, 'create_post.html')

@login_required
def add_comment(request, post_id):
    if request.method == 'POST':
        post = get_object_or_404(Post, id=post_id)
        text = request.POST.get('comment')

        comment = Comment(post=post, user=request.user, text=text)
        comment.save()
        if request.user != post.user: 
            Notification.objects.create(
                user=post.user, 
                from_user=request.user,  
                notification_type='comment', 
                post=post
            )
        messages.success(request, 'Comment added successfully!')
        return redirect('post_detail', post_id=post.id)
    return redirect('post_detail', post_id=post_id)
from .models import Notification
@login_required
def like_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)

    if request.user in post.likes.all():
        post.likes.remove(request.user)
        messages.success(request, 'Post unliked.')
    else:
        post.likes.add(request.user)
        messages.success(request, 'Post liked.')

        # Create a notification for the post owner
        if request.user != post.user:  # Prevent self-notification
            Notification.objects.create(
                user=post.user, 
                from_user=request.user,  # Who liked the post
                notification_type='like', 
                post=post
            )

    return redirect('post_detail', post_id=post_id)

def post_detail(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    return render(request, 'post_detail.html', {'post': post})

def user_posts(request, username):
    user = get_object_or_404(User, username=username)
    posts = user.posts.all()
    return render(request, 'user_posts.html', {'user': user, 'posts': posts})


def add_reply(request, comment_id):
    if request.method == 'POST':
        comment = get_object_or_404(Comment, id=comment_id)
        text = request.POST.get('reply')

        reply = Comment(post=comment.post, user=request.user, text=text, parent=comment)
        reply.save()

        messages.success(request, 'Reply added successfully!')
        return redirect('post_detail', post_id=comment.post.id)
    return redirect('post_detail', post_id=comment.post.id)



from django.core.paginator import Paginator
def user_search(request):
    query = request.GET.get('q', '')
    users = User.objects.none()  

    if query:
        users = User.objects.filter(
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    paginator = Paginator(users, 10)  
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'user_search.html', {
        'query': query,
        'page_obj': page_obj,
    })

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import get_user_model
from .models import Post
User = get_user_model()
def user_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    is_private_profile = user.is_private
    is_friend = Friendship.objects.filter(user1=user, user2=request.user).exists() or \
                Friendship.objects.filter(user1=request.user, user2=user).exists()
    friend_requests = FriendRequest.objects.filter(to_user=user)
    if not is_private_profile or is_friend:
        posts = Post.objects.filter(author=user)
    else:
        posts = []

    context = {
        'user': user,
        'friend_requests': friend_requests,
        'posts': posts,
        'is_friend': is_friend,

    }

    return render(request, 'core/user_profile.html', context)



from django.shortcuts import render, get_object_or_404
from .models import CustomUser, Post, Friendship  
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect

@login_required
def my_profile_view(request, username):

    user_profile = get_object_or_404(CustomUser, username=username)
    if request.user != user_profile:      
        return redirect('my_profile_view', username=request.user.username) 
    user_posts = Post.objects.filter(user=user_profile).order_by('-created_at')
    
    followers_count = Friendship.objects.filter(user2=user_profile).count()  
    following_count = Friendship.objects.filter(user1=user_profile).count()  
    context = {
        'user': user_profile,
        'posts': user_posts,
        'followers_count': followers_count,
        'following_count': following_count,
    }

    return render(request, 'my_profile.html', context)





from django.contrib.auth import logout

def custom_logout(request):
    logout(request)  
    return redirect('login_view')
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import FriendRequest, Friendship
from django.contrib.auth import get_user_model

User = get_user_model()

# Send a friend request
from django.urls import reverse

def send_friend_request(request, user_id):
    to_user = get_object_or_404(User, id=user_id)
    from_user = request.user

    if from_user == to_user:
        messages.error(request, 'You cannot send a friend request to yourself.')
        return redirect('profile_view', username=from_user.username)  # Redirect to your own profile

    if FriendRequest.objects.filter(from_user=from_user, to_user=to_user).exists():
        messages.warning(request, 'Friend request already sent.')
    else:
        FriendRequest.objects.create(from_user=from_user, to_user=to_user)
        messages.success(request, 'Friend request sent.')

    return redirect('profile_view', username=to_user.username) 

# Accept a friend request
@login_required
def accept_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, id=request_id)

    # Ensure the logged-in user is the recipient of the request
    if friend_request.to_user == request.user:
        # Check if friendship already exists to prevent duplicates
        friendship_exists = Friendship.objects.filter(
            user1=friend_request.from_user,
            user2=friend_request.to_user
        ).exists()
        
        if friendship_exists:
            messages.warning(request, 'You are already friends with this user.')
        else:
            # Create a friendship
            Friendship.objects.create(user1=friend_request.from_user, user2=friend_request.to_user)
            messages.success(request, 'Friend request accepted.')

        # Delete the friend request regardless of the friendship status
        friend_request.delete()
    else:
        messages.error(request, 'Invalid request.')

    return redirect('friend_requests')


# Reject a friend request
@login_required
def reject_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, id=request_id)

    # Ensure the logged-in user is the recipient of the request
    if friend_request.to_user == request.user:
        friend_request.delete()
        messages.success(request, 'Friend request rejected.')
    else:
        messages.error(request, 'Invalid request.')

    return redirect('friend_requests')

# List of friend requests
@login_required
def friend_requests_list(request):
    received_requests = FriendRequest.objects.filter(to_user=request.user)
    sent_requests = FriendRequest.objects.filter(from_user=request.user)

    context = {
        'received_requests': received_requests,
        'sent_requests': sent_requests
    }

    return render(request, 'friend_requests.html', context)






@login_required
def notifications(request):
    # Fetch all notifications for the logged-in user, ordered by creation date
    user_notifications = request.user.notifications.all().order_by('-created_at')

    # Optionally mark notifications as read when viewed
    for notification in user_notifications:
        notification.is_read = True
        notification.save()

    # Assuming you also want to handle friend requests, you'll need this line
    received_requests = request.user.received_friend_requests.all()  # Adjust as necessary

    return render(request, 'notifications.html', {
        'notifications': user_notifications,
        'received_requests': received_requests
    })


def friends_list(request, username):
    # Fetch the user profile
    user_profile = get_object_or_404(CustomUser, username=username)

    # Fetch all friendships for the user
    friendships = Friendship.objects.filter(user1=user_profile)

    # Get the friend users
    friends_users = [friend.user2 for friend in friendships]

    context = {
        'user': user_profile,
        'friends': friends_users,
    }

    return render(request, 'friends_list.html', context)

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

@login_required
def privacy_settings(request):
    user = request.user  # Get the currently logged-in user

    if request.method == 'POST':
        # Get the value of 'is_private' from the form, which will be 'on' if checked
        is_private = request.POST.get('is_private') == 'on'
        user.is_private = is_private  # Set the value for 'is_private'
        user.save()  # Save the updated privacy setting

        return redirect('my_profile_view', username=user.username)
    return render(request, 'privacy_settings.html', {'is_private': user.is_private})







from django.contrib import messages
from .models import Conversation, Message, User


@login_required
def conversation_list(request):
    # Get all conversations the user is a part of
    conversations = request.user.conversations.all().order_by('-last_updated')
    return render(request, 'messaging/conversation_list.html', {'conversations': conversations})

@login_required
def conversation_detail(request, conversation_id):
    # Get the conversation and its messages
    conversation = get_object_or_404(Conversation, id=conversation_id)
    
    if request.user not in conversation.participants.all():
        messages.error(request, "You are not a participant in this conversation.")
        return redirect('conversation_list')

    if request.method == 'POST':
        message_text = request.POST.get('message')
        if message_text:
            Message.objects.create(
                conversation=conversation,
                sender=request.user,
                text=message_text
            )
            # Update the conversation's last updated timestamp
            conversation.save()
        return redirect('conversation_detail', conversation_id=conversation_id)

    messages = conversation.messages.order_by('timestamp')
    return render(request, 'conversation_detail.html', {'conversation': conversation, 'messages': messages})

@login_required
def start_conversation(request, user_id):
    recipient = get_object_or_404(User, id=user_id)
    
    if recipient == request.user:
        messages.error(request, "You cannot start a conversation with yourself.")
        return redirect('conversation_list')

    # Check if a conversation already exists between these two users
    existing_conversation = Conversation.objects.filter(participants=request.user).filter(participants=recipient).first()
    if existing_conversation:
        return redirect('conversation_detail', conversation_id=existing_conversation.id)
    
    # If no conversation exists, create a new one
    new_conversation = Conversation.objects.create()
    new_conversation.participants.add(request.user, recipient)
    new_conversation.save()
    
    return redirect('conversation_detail', conversation_id=new_conversation.id)


def send_message(request, recipient_id):
    recipient = get_object_or_404(User, id=recipient_id)

    # Check if a conversation exists between these two users
    conversation = Conversation.objects.filter(participants=request.user).filter(participants=recipient).first()

    if not conversation:
        # Create a new conversation if none exists
        conversation = Conversation.objects.create()
        conversation.participants.add(request.user, recipient)
        conversation.save()

    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            # Save the message in the conversation
            Message.objects.create(
                conversation=conversation,
                sender=request.user,
                text=content
            )
            return redirect('conversation_detail', conversation_id=conversation.id)

    # Fetch all messages for the conversation to display
    messages = conversation.messages.order_by('timestamp')
    
    return render(request, 'send_message.html', {
        'recipient': recipient,
        'conversation': conversation,
        'messages': messages,
    })


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Post

@login_required
def edit_post(request, post_id):
    post = get_object_or_404(Post, id=post_id, user=request.user)

    if request.method == "POST":
        caption = request.POST.get("caption", post.caption)
        location = request.POST.get("location", post.location)
        image = request.FILES.get("image", post.image)

        # Update post fields
        post.caption = caption
        post.location = location
        if image:
            post.image = image  # Only update image if a new one was uploaded
        post.save()

        messages.success(request, "Post updated successfully.")
        return redirect("post_detail", post_id=post.id)

    return render(request, "edit_post.html", {"post": post})


@login_required
def delete_post(request, post_id):
    post = get_object_or_404(Post, id=post_id, user=request.user)

    if request.method == "POST":
        post.delete()
        messages.success(request, "Post deleted successfully.")
        return redirect("my_profile_view", username=request.user.username)  # Pass the username here

    return render(request, "delete_post.html", {"post": post})
