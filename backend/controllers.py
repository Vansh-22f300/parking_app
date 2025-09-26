from flask_restful import Resource, Api
from flask import request, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import db, User, ParkingLot, ParkingSpot, ReserveSpot
from datetime import datetime, timedelta
import calendar
import math
import json

# Redis utility functions
def get_redis_client():
    """Get Redis client from Flask app context"""
    return getattr(current_app, 'redis_client', None)

def cache_set(key, value, expiry_seconds=300):
    """Set cache with expiry"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            redis_client.setex(key, expiry_seconds, json.dumps(value))
            return True
        except Exception as e:
            print(f"Redis cache set error: {e}")
    return False

def cache_get(key):
    """Get cached value"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            cached_data = redis_client.get(key)
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            print(f"Redis cache get error: {e}")
    return None

def cache_delete(key):
    """Delete cache key"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            redis_client.delete(key)
            return True
        except Exception as e:
            print(f"Redis cache delete error: {e}")
    return False

def clear_all_cache():
    """Clear all application cache"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            # Get all cache keys
            cache_keys = redis_client.keys('users:*') + redis_client.keys('user:*') + redis_client.keys('parking_lot*')
            if cache_keys:
                redis_client.delete(*cache_keys)
            print(f"✅ Cleared {len(cache_keys)} cache keys")
            return True
        except Exception as e:
            print(f"Redis cache clear error: {e}")
    return False

def increment_counter(key):
    """Increment counter in Redis"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            return redis_client.incr(key)
        except Exception as e:
            print(f"Redis counter error: {e}")
    return 0

def add_to_set(key, value, expiry_seconds=3600):
    """Add value to Redis set"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            redis_client.sadd(key, value)
            redis_client.expire(key, expiry_seconds)
            return True
        except Exception as e:
            print(f"Redis set error: {e}")
    return False

def rate_limit_check(user_id, endpoint, max_requests=100, window_seconds=3600):
    """Check rate limit for user"""
    redis_client = get_redis_client()
    if redis_client:
        try:
            key = f'rate_limit:{user_id}:{endpoint}'
            current_requests = redis_client.get(key)
            
            if current_requests is None:
                redis_client.setex(key, window_seconds, 1)
                return True
            elif int(current_requests) < max_requests:
                redis_client.incr(key)
                return True
            else:
                return False
        except Exception as e:
            print(f"Redis rate limit error: {e}")
    return True  # Allow if Redis is unavailable

class UserResource(Resource):
    @jwt_required()
    def get(self, user_id=None):
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        # Rate limiting
        if not rate_limit_check(current_user_id, 'get_users', 50, 3600):
            return {'msg': 'Rate limit exceeded. Try again later.'}, 429
        
        # Increment API usage counter
        increment_counter('api_calls:users:get')
        
        if user_id:
            # Only allow users to access their own data or admin to access any
            if current_user.role != 'admin' and current_user_id != user_id:
                return {'msg': 'Access denied'}, 403
            
            # Try to get user from cache first
            cache_key = f'user:{user_id}'
            cached_user = cache_get(cache_key)
            if cached_user:
                return cached_user, 200
                
            user = User.query.get(user_id)
            if user:
                user_data = {
                    'msg': 'User found',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role,
                        'vehicle_number': user.vehicle_number,
                        'phone_number': user.phone_number if user.phone_number else None
                    }
                }
                # Cache user data for 10 seconds only to prevent stale data
                cache_set(cache_key, user_data, 10)
                return user_data, 200
            return {'msg': 'User not found'}, 404
        
        if current_user.role != 'admin':
            return {'msg': 'Access denied. Admin only.'}, 403
        
        cache_key = 'users:all'
        cached_users = cache_get(cache_key)
        if cached_users:
            return cached_users, 200
            
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'vehicle_number': user.vehicle_number,
                'phone_number': user.phone_number
            })
        
        response_data = {'msg': 'Users retrieved successfully', 'users': user_list}
        # Cache users list for 10 seconds only to prevent stale data
        cache_set(cache_key, response_data, 10)
        return response_data, 200
    
    def post(self):
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        vehicle_number = data.get('vehicle_number')
        phone_number = data.get('phone_number', None)
        
        if not email or not username or not password:
            return {'msg': 'Please provide email, username, and password'}, 400
        
        # Normalize email and username
        email = email.lower().strip()
        username = username.strip()
        
        # Check if user already exists (case-insensitive)
        existing_user = User.query.filter(User.email.ilike(email)).first()
        if existing_user:
            return {'msg': f'User with email {email} already exists'}, 400
        
        # Check if username already exists (case-insensitive)
        existing_username = User.query.filter(User.username.ilike(username)).first()
        if existing_username:
            return {'msg': f'Username {username} already exists'}, 400
        
        # Check if vehicle number already exists (only if provided)
        if vehicle_number:
            existing_vehicle = User.query.filter_by(vehicle_number=vehicle_number).first()
            if existing_vehicle:
                return {'msg': 'Vehicle number already exists'}, 400
        
        # Create new user
        user = User(
            email=email,
            username=username,
            password=password,
            role=role,
            vehicle_number=vehicle_number if vehicle_number else None,
            phone_number=phone_number if 'phone_number' in data else None
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Invalidate users cache when new user is created
            cache_delete('users:all')
            increment_counter('users_created')
            
            return {
                'msg': 'User created successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'vehicle_number': user.vehicle_number,
                    'phone_number': user.phone_number
                }
            }, 201
        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            if 'UNIQUE constraint failed: user.email' in error_msg:
                return {'msg': 'Email already exists'}, 400
            elif 'UNIQUE constraint failed: user.username' in error_msg:
                return {'msg': 'Username already exists'}, 400
            elif 'UNIQUE constraint failed: user.vehicle_number' in error_msg:
                return {'msg': 'Vehicle number already exists'}, 400
            else:
                return {'msg': 'Error creating user', 'error': str(e)}, 500
    
    @jwt_required()
    def put(self, user_id):
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        # Convert user_id to int for proper comparison
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return {'msg': 'Invalid user ID'}, 400
        
        # Only allow users to update their own data or admin to update any
        if current_user.role != 'admin' and current_user_id != user_id:
            return {'msg': 'Access denied'}, 403
            
        user = User.query.get(user_id)
        if not user:
            return {'msg': 'User not found'}, 404
        
        data = request.get_json()
        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'password' in data:
            user.password = data['password']
        if 'role' in data and current_user.role == 'admin':
            user.role = data['role']
        if 'vehicle_number' in data:
            # Check if vehicle number is unique (only if it's different from current)
            if data['vehicle_number'] and data['vehicle_number'] != user.vehicle_number:
                existing_vehicle = User.query.filter_by(vehicle_number=data['vehicle_number']).first()
                if existing_vehicle:
                    return {'msg': 'Vehicle number already exists'}, 409
            user.vehicle_number = data['vehicle_number']
        if 'phone_number' in data:
            # Check if phone number is unique (only if it's different from current)
            if data['phone_number'] and data['phone_number'] != user.phone_number:
                existing_phone = User.query.filter_by(phone_number=data['phone_number']).first()
                if existing_phone:
                    return {'msg': 'Phone number already exists'}, 409
            user.phone_number = data['phone_number']
        
        try:
            db.session.commit()
            
            # Invalidate user cache when updated
            cache_delete(f'user:{user.id}')
            cache_delete('users:all')
            
            return {
                'msg': 'User updated successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'vehicle_number': user.vehicle_number,
                    'phone_number': user.phone_number
                }
            }, 200
        except Exception as e:
            db.session.rollback()
            return {'msg': 'Error updating user', 'error': str(e)}, 500
    
    @jwt_required()
    def delete(self, user_id):
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        # Only admin can delete users
        if current_user.role != 'admin':
            return {'msg': 'Access denied. Admin only.'}, 403
            
        user = User.query.get(user_id)
        if not user:
            return {'msg': 'User not found'}, 404
        
        # Prevent deletion of admin users (optional safety check)
        if user.role == 'admin':
            return {'msg': 'Cannot delete admin users for security reasons'}, 403
        
        try:
            # Handle related records before deleting user
            
            # 1. Check for active reservations
            active_reservations = ReserveSpot.query.filter_by(user_id=user_id).filter(
                ReserveSpot.leaving_time.is_(None)
            ).all()
            
            if active_reservations:
                # Release all active parking spots and complete reservations
                for reservation in active_reservations:
                    spot = ParkingSpot.query.get(reservation.spot_id)
                    if spot:
                        spot.status = 'available'
                        spot.user_id = None
                        
                        # Update available slots in the parking lot
                        lot = ParkingLot.query.get(spot.lot_id)
                        if lot:
                            lot.available_slots += 1
                    
                    # Mark reservation as completed with current time
                    reservation.leaving_time = datetime.now()
                    
                    # Calculate final cost if not already set
                    if reservation.parking_cost == 0:
                        lot = ParkingLot.query.get(spot.lot_id) if spot else None
                        if lot:
                            duration_hours = (reservation.leaving_time - reservation.parking_time).total_seconds() / 3600
                            reservation.parking_cost = duration_hours * lot.price
            
            # 2. Clear user_id from any parking spots still assigned to this user
            assigned_spots = ParkingSpot.query.filter_by(user_id=user_id).all()
            for spot in assigned_spots:
                spot.user_id = None
                spot.status = 'available'
                
                # Update available slots
                lot = ParkingLot.query.get(spot.lot_id)
                if lot:
                    lot.available_slots += 1
            
            # 3. Delete ALL reservations (both active and historical) for this user
            # This is necessary to avoid foreign key constraint violations
            all_reservations = ReserveSpot.query.filter_by(user_id=user_id).all()
            for reservation in all_reservations:
                db.session.delete(reservation)
            
            # 4. Now safe to delete the user
            db.session.delete(user)
            db.session.commit()
            
            # Invalidate caches
            cache_delete(f'user:{user_id}')
            cache_delete('users:all')
            cache_delete('parking_lots:all')  # Since we may have updated availability
            increment_counter('users_deleted')
            
            return {'msg': 'User deleted successfully. Any active reservations have been completed, parking spots released, and reservation history removed.'}, 200
        except Exception as e:
            db.session.rollback()
            import traceback
            print(f"Error deleting user {user_id}: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            return {'msg': 'Error deleting user', 'error': str(e), 'details': traceback.format_exc()}, 500


class ParkingLotResource(Resource):
    
    def get(self, lot_id=None):
        # Increment API usage counter
        increment_counter('api_calls:parking_lots:get')
        
        if lot_id:
            # Try to get parking lot from cache first
            cache_key = f'parking_lot:{lot_id}'
            cached_lot = cache_get(cache_key)
            if cached_lot:
                return cached_lot, 200
                
            lot = ParkingLot.query.get(lot_id)
            if lot:
                lot_data = {
                    'msg': 'Parking lot found',
                    'lot': {
                        'id': lot.id,
                        'location_name': lot.location_name,
                        'price': lot.price,
                        'address': lot.address,
                        'pincode': lot.pincode,
                        'number_of_slots': lot.number_of_slots,
                        'available_slots': lot.available_slots
                    }
                }
                # Cache parking lot data for 10 seconds only to prevent stale data
                cache_set(cache_key, lot_data, 10)
                return lot_data, 200
            return {'msg': 'Parking lot not found'}, 404
        
        # Try to get all parking lots from cache
        cache_key = 'parking_lots:all'
        cached_lots = cache_get(cache_key)
        if cached_lots:
            return cached_lots, 200
        
        lots = ParkingLot.query.all()
        lot_list = []
        for lot in lots:
            lot_list.append({
                'id': lot.id,
                'location_name': lot.location_name,
                'price': lot.price,
                'address': lot.address,
                'pincode': lot.pincode,
                'number_of_slots': lot.number_of_slots,
                'available_slots': lot.available_slots
            })
        
        response_data = {'msg': 'Parking lots retrieved successfully', 'lots': lot_list}
        # Cache parking lots for 10 seconds only (they change frequently)
        cache_set(cache_key, response_data, 10)
        return response_data, 200
    
    @jwt_required()
    def post(self):
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        # Only admin can create parking lots
        if current_user.role != 'admin':
            return {'msg': 'Access denied. Admin only.'}, 403
        
        data = request.get_json()
        location_name = data.get('location_name')
        price = data.get('price')
        address = data.get('address')
        pincode = data.get('pincode')
        number_of_slots = data.get('number_of_slots')
        
        if not all([location_name, price, address, pincode, number_of_slots]):
            return {'msg': 'Please provide all required fields'}, 400
        
        try:
            lot = ParkingLot(
                location_name=location_name,
                price=float(price),
                address=address,
                pincode=pincode,
                number_of_slots=int(number_of_slots),
                available_slots=int(number_of_slots)
            )
            
            db.session.add(lot)
            db.session.commit()
            
            # Create parking spots for this lot
            for i in range(int(number_of_slots)):
                spot = ParkingSpot(
                    lot_id=lot.id,
                    status='available'
                )
                db.session.add(spot)
            
            db.session.commit()
            
            # Invalidate parking lots cache when new lot is created
            cache_delete('parking_lots:all')
            increment_counter('parking_lots_created')
            
            return {
                'msg': 'Parking lot created successfully',
                'lot': {
                    'id': lot.id,
                    'location_name': lot.location_name,
                    'price': lot.price,
                    'address': lot.address,
                    'pincode': lot.pincode,
                    'number_of_slots': lot.number_of_slots,
                    'available_slots': lot.available_slots
                }
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'msg': 'Error creating parking lot', 'error': str(e)}, 500
    
    @jwt_required()
    def put(self, lot_id):
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        # Only admin can update parking lots
        if current_user.role != 'admin':
            return {'msg': 'Access denied. Admin only.'}, 403
        
        lot = ParkingLot.query.get(lot_id)
        if not lot:
            return {'msg': 'Parking lot not found'}, 404
        
        data = request.get_json()
        if 'location_name' in data:
            lot.location_name = data['location_name']
        if 'price' in data:
            lot.price = float(data['price'])
        if 'address' in data:
            lot.address = data['address']
        if 'pincode' in data:
            lot.pincode = data['pincode']
        if 'number_of_slots' in data:
            lot.number_of_slots = int(data['number_of_slots'])
        if 'available_slots' in data:
            lot.available_slots = int(data['available_slots'])
        
        try:
            db.session.commit()
            
            # Invalidate parking lot cache when updated
            cache_delete(f'parking_lot:{lot_id}')
            cache_delete('parking_lots:all')
            
            return {
                'msg': 'Parking lot updated successfully',
                'lot': {
                    'id': lot.id,
                    'location_name': lot.location_name,
                    'price': lot.price,
                    'address': lot.address,
                    'pincode': lot.pincode,
                    'number_of_slots': lot.number_of_slots,
                    'available_slots': lot.available_slots
                }
            }, 200
        except Exception as e:
            db.session.rollback()
            return {'msg': 'Error updating parking lot', 'error': str(e)}, 500
    
    @jwt_required()
    def delete(self, lot_id):
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        # Only admin can delete parking lots
        if current_user.role != 'admin':
            return {'msg': 'Access denied. Admin only.'}, 403
        
        lot = ParkingLot.query.get(lot_id)
        if not lot:
            return {'msg': 'Parking lot not found'}, 404
        
        try:
            # Delete all spots in this lot first
            ParkingSpot.query.filter_by(lot_id=lot_id).delete()
            db.session.delete(lot)
            db.session.commit()
            
            # Invalidate parking lot cache when deleted
            cache_delete(f'parking_lot:{lot_id}')
            cache_delete('parking_lots:all')
            increment_counter('parking_lots_deleted')
            
            return {'msg': 'Parking lot deleted successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'msg': 'Error deleting parking lot', 'error': str(e)}, 500


class ParkingSpotResource(Resource):
    
    def get(self, spot_id=None):
        if spot_id:
            spot = ParkingSpot.query.get(spot_id)
            if spot:
                return {
                    'msg': 'Parking spot found',
                    'spot': {
                        'id': spot.id,
                        'lot_id': spot.lot_id,
                        'user_id': spot.user_id,
                        'status': spot.status
                    }
                }, 200
            return {'msg': 'Parking spot not found'}, 404
        
        spots = ParkingSpot.query.all()
        spot_list = []
        for spot in spots:
            spot_list.append({
                'id': spot.id,
                'lot_id': spot.lot_id,
                'user_id': spot.user_id,
                'status': spot.status
            })
        return {'msg': 'Parking spots retrieved successfully', 'spots': spot_list}, 200
    
    def put(self, spot_id):
        spot = ParkingSpot.query.get(spot_id)
        if not spot:
            return {'msg': 'Parking spot not found'}, 404
        
        data = request.get_json()
        if 'user_id' in data:
            spot.user_id = data['user_id']
        if 'status' in data:
            spot.status = data['status']
        
        try:
            db.session.commit()
            return {
                'msg': 'Parking spot updated successfully',
                'spot': {
                    'id': spot.id,
                    'lot_id': spot.lot_id,
                    'user_id': spot.user_id,
                    'status': spot.status
                }
            }, 200
        except Exception as e:
            db.session.rollback()
            return {'msg': 'Error updating parking spot', 'error': str(e)}, 500


class AvailableSpotsResource(Resource):
    
    def get(self, lot_id):
        """Get available spots for a specific parking lot"""
        lot = ParkingLot.query.get(lot_id)
        if not lot:
            return {'msg': 'Parking lot not found'}, 404
        
        available_spots = ParkingSpot.query.filter_by(
            lot_id=lot_id,
            status='available'
        ).all()
        
        spot_list = []
        for spot in available_spots:
            spot_list.append({
                'id': spot.id,
                'lot_id': spot.lot_id,
                'status': spot.status
            })
        
        return {
            'msg': 'Available spots retrieved successfully',
            'lot_name': lot.location_name,
            'available_spots': spot_list,
            'count': len(spot_list)
        }, 200


class LoginResource(Resource):
    
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return {'msg': 'Please provide email and password'}, 400
        
        user = User.query.filter_by(email=email).first()
        if not user or user.password != password:
            return {'msg': 'Invalid credentials'}, 401
        
        # Create JWT token with string identity
        access_token = create_access_token(identity=str(user.id))
        
        # Cache user session data for 12 hours
        session_data = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'vehicle_number': user.vehicle_number,
            'login_time': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat()
        }
        cache_set(f'user_session:{user.id}', session_data, 43200)  # 12 hours
        
        # Add user to active users set
        add_to_set('active_users', user.id, 43200)
        
        # Increment login counter
        increment_counter('total_logins')
        increment_counter(f'daily_logins:{datetime.now().strftime("%Y-%m-%d")}')
        
        return {
            'msg': 'Login successful',
            'token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'vehicle_number': user.vehicle_number
            }
        }, 200


class RegisterResource(Resource):
    
    def post(self):
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        vehicle_number = data.get('vehicle_number')
        phone_number = data.get('phone_number')
        
        if not email or not username or not password:
            return {'msg': 'Please provide email, username, and password'}, 400
        
        # Normalize email to lowercase for consistent checking
        email = email.lower().strip()
        username = username.strip()
        
        try:
            # Check if user already exists (case-insensitive email check)
            existing_user = User.query.filter(User.email.ilike(email)).first()
            if existing_user:
                return {'msg': f'User with email {email} already exists'}, 409
            
            # Check if username already exists (case-insensitive)
            existing_username = User.query.filter(User.username.ilike(username)).first()
            if existing_username:
                return {'msg': f'Username {username} already exists'}, 409
            
            # Check if vehicle number already exists (only if provided)
            if vehicle_number and vehicle_number.strip():
                vehicle_number = vehicle_number.strip()
                existing_vehicle = User.query.filter_by(vehicle_number=vehicle_number).first()
                if existing_vehicle:
                    return {'msg': 'Vehicle number already exists'}, 409
            
            # Check if phone number already exists (only if provided)
            if phone_number and phone_number.strip():
                phone_number = phone_number.strip()
                existing_phone = User.query.filter_by(phone_number=phone_number).first()
                if existing_phone:
                    return {'msg': 'Phone number already exists'}, 409
        except Exception as e:
            print(f"Error during user validation: {str(e)}")
            return {'msg': 'Database error during validation'}, 500
        
        # Create new user
        user = User(
            email=email,
            username=username,
            password=password,
            role=role,
            vehicle_number=vehicle_number if vehicle_number else None,
            phone_number=phone_number if phone_number else None
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Create JWT token for immediate login with string identity
            access_token = create_access_token(identity=str(user.id))
            
            # Cache user session data for 12 hours (auto-login after registration)
            session_data = {
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'vehicle_number': user.vehicle_number,
                'login_time': datetime.now().isoformat(),
                'last_activity': datetime.now().isoformat()
            }
            cache_set(f'user_session:{user.id}', session_data, 43200)  # 12 hours
            
            # Add user to active users set
            add_to_set('active_users', user.id, 43200)
            
            # Increment registration counter
            increment_counter('total_registrations')
            increment_counter(f'daily_registrations:{datetime.now().strftime("%Y-%m-%d")}')
            
            # Invalidate users cache
            cache_delete('users:all')
            
            # Send welcome email
            # Email functionality not implemented yet
            
            return {
                'msg': 'User registered successfully',
                'token': access_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'vehicle_number': user.vehicle_number,
                    'phone_number': user.phone_number
                }
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'msg': 'Registration failed. Please try again.'}, 500


class LogoutResource(Resource):
    @jwt_required()
    def post(self):
        """Handle user logout and clear Redis session"""
        current_user_id = int(get_jwt_identity())
        
        # Clear user session from Redis
        cache_delete(f'user_session:{current_user_id}')
        
        # Remove user from active users set
        redis_client = get_redis_client()
        if redis_client:
            try:
                redis_client.srem('active_users', current_user_id)
            except Exception as e:
                print(f"Redis set removal error: {e}")
        
        # Increment logout counter
        increment_counter('total_logouts')
        
        return {'msg': 'Logged out successfully'}, 200

