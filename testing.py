import random
import math
import datetime
from collections import defaultdict, Counter
import json
import os

class DummyUser:
    def __init__(self, name, age, email):
        self.name = name
        self.age = age
        self.email = email
        self.created_at = datetime.datetime.now()

    def greet(self):
        return f"Hello, I'm {self.name}, {self.age} years old!"

    def update_email(self, new_email):
        if '@' in new_email:
            self.email = new_email
            return True
        return False

    def calculate_birth_year(self):
        current_year = datetime.datetime.now().year
        return current_year - self.age

class DummyProduct:
    def __init__(self, name, price, category):
        self.name = name
        self.price = price
        self.category = category
        self.in_stock = True

    def apply_discount(self, percentage):
        if 0 <= percentage <= 100:
            discount_amount = self.price * (percentage / 100)
            self.price -= discount_amount
            return self.price
        return None

    def toggle_stock(self):
        self.in_stock = not self.in_stock
        return self.in_stock

class DummyCalculator:
    @staticmethod
    def add(a, b):
        return a + b

    @staticmethod
    def multiply(a, b):
        return a * b

    @staticmethod
    def power(base, exponent):
        return math.pow(base, exponent)

def generate_random_users(count):
    users = []
    names = ["Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry"]
    domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

    for i in range(count):
        name = random.choice(names)
        age = random.randint(18, 80)
        email = f"{name.lower()}{i}@{random.choice(domains)}"
        users.append(DummyUser(name, age, email))

    return users

def process_products(products):
    total_value = 0
    categories = Counter()

    for product in products:
        total_value += product.price
        categories[product.category] += 1

    return {
        'total_value': total_value,
        'category_counts': dict(categories),
        'average_price': total_value / len(products) if products else 0
    }

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

def string_manipulator(text):
    try:
        # Convert to uppercase
        upper = text.upper()

        # Reverse the string
        reversed_text = text[::-1]

        # Count vowels
        vowels = 'aeiouAEIOU'
        vowel_count = sum(1 for char in text if char in vowels)

        # Split into words
        words = text.split()

        return {
            'original': text,
            'uppercase': upper,
            'reversed': reversed_text,
            'vowel_count': vowel_count,
            'word_count': len(words)
        }
    except Exception as e:
        return f"Error processing text: {str(e)}"

def data_processor(data_list):
    processed = defaultdict(list)

    for item in data_list:
        if isinstance(item, int):
            processed['numbers'].append(item * 2)
        elif isinstance(item, str):
            processed['strings'].append(item.upper())
        elif isinstance(item, float):
            processed['floats'].append(round(item, 2))
        else:
            processed['others'].append(str(item))

    return dict(processed)

def file_operations_demo():
    try:
        # Create a temporary file
        with open('temp_demo.txt', 'w') as f:
            f.write("This is a demo file\n")
            f.write("Line 2\n")
            f.write("Line 3\n")

        # Read the file
        with open('temp_demo.txt', 'r') as f:
            content = f.read()

        # Clean up
        if os.path.exists('temp_demo.txt'):
            os.remove('temp_demo.txt')

        return content
    except Exception as e:
        return f"File operation failed: {str(e)}"

def main():
    # Create dummy users
    users = generate_random_users(5)
    print("Generated users:")
    for user in users:
        print(f"  {user.greet()}")

    # Create dummy products
    products = [
        DummyProduct("Laptop", 999.99, "Electronics"),
        DummyProduct("Book", 19.99, "Education"),
        DummyProduct("Coffee Mug", 9.99, "Kitchen"),
        DummyProduct("Headphones", 79.99, "Electronics")
    ]

    # Process products
    product_stats = process_products(products)
    print("\nProduct statistics:")
    print(json.dumps(product_stats, indent=2))

    # Calculator operations
    calc = DummyCalculator()
    print(f"\nCalculator: 5 + 3 = {calc.add(5, 3)}")
    print(f"Calculator: 4 * 7 = {calc.multiply(4, 7)}")
    print(f"Calculator: 2^8 = {calc.power(2, 8)}")

    # Fibonacci
    fib_10 = fibonacci(10)
    print(f"\nFibonacci(10) = {fib_10}")

    # String manipulation
    text_result = string_manipulator("Hello World! This is a test string.")
    print(f"\nString manipulation result:")
    print(json.dumps(text_result, indent=2))

    # Data processing
    mixed_data = [1, "hello", 3.14, 42, "world", 2.71, True]
    processed_data = data_processor(mixed_data)
    print(f"\nProcessed mixed data:")
    print(json.dumps(processed_data, indent=2))

    # File operations
    file_content = file_operations_demo()
    print(f"\nFile operations result:\n{file_content}")

if __name__ == "__main__":
    main()
