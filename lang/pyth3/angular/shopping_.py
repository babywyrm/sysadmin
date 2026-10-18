Sure! Here's an example of a single application that combines Angular for the frontend and Flask for the backend. It demonstrates a simple shopping cart webpage with multiple functions and classes. Additionally, it includes basic security measures provided by Angular.

####
####

Backend (Flask):
python
Copy code
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/api/products', methods=['GET'])
def get_products():
    products = [
        {'id': 1, 'name': 'Product 1', 'price': 10},
        {'id': 2, 'name': 'Product 2', 'price': 20},
        {'id': 3, 'name': 'Product 3', 'price': 30}
    ]
    return jsonify(products)

@app.route('/api/checkout', methods=['POST'])
def checkout():
    data = request.get_json()
    items = data.get('items', [])
    total = sum(item['price'] for item in items)
    return jsonify({'total': total})

if __name__ == '__main__':
    app.run(debug=True)
    
####
####

Frontend (Angular):
Create a new Angular project by running the following commands:

bash
Copy code
ng new shopping-cart
cd shopping-cart
Replace the contents of src/app/app.component.html with the following:

html
Copy code
<h1>Shopping Cart</h1>

<div *ngIf="loading">Loading...</div>

<div *ngIf="!loading">
  <div *ngFor="let product of products">
    <h3>{{ product.name }}</h3>
    <p>Price: ${{ product.price }}</p>
    <button (click)="addToCart(product)">Add to Cart</button>
  </div>

  <h2>Cart</h2>
  <div *ngFor="let item of cartItems">
    <h4>{{ item.name }}</h4>
    <p>Price: ${{ item.price }}</p>
  </div>

  <button (click)="checkout()">Checkout</button>
</div>

<p *ngIf="checkoutSuccess">Checkout successful. Total: ${{ total }}</p>
    
##
##

Replace the contents of src/app/app.component.ts with the following:

typescript
Copy code
import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';

interface Product {
  id: number;
  name: string;
  price: number;
}

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  loading = true;
  products: Product[] = [];
  cartItems: Product[] = [];
  checkoutSuccess = false;
  total = 0;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.getProducts();
  }

  getProducts(): void {
    this.http.get<Product[]>('/api/products').subscribe(products => {
      this.products = products;
      this.loading = false;
    });
  }

  addToCart(product: Product): void {
    this.cartItems.push(product);
  }

  checkout(): void {
    this.http.post<any>('/api/checkout', { items: this.cartItems }).subscribe(response => {
      this.total = response.total;
      this.checkoutSuccess = true;
      this.cartItems = [];
    });
  }
}

##
##

Make sure you have the necessary dependencies installed by running npm install in the project directory.

Finally, start the Angular development server:


ng serve


Now you can visit http://localhost:4200 in your browser to see the shopping cart webpage. Angular's security measures, such as sanitization and cross-site
