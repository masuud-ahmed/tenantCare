require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const sqlite3 = require('sqlite3').verbose();

// Add body-parser middleware to it
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cors());

// Connect it to the SQLite database
const db = new sqlite3.Database('./database.sqlite');

const port = process.env.PORT || 9001;
// Secret key for JWT
const secretKey = 'your-secret-key';

// Create tables in the database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS landlords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    landlord_id INTEGER,
    title TEXT,
    description TEXT,
    address TEXT,
    rent_fee INTEGER,
    availability INTEGER DEFAULT 0 CHECK(availability IN (0, 1)),
    image TEXT,
    FOREIGN KEY(landlord_id) REFERENCES landlords(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tenant_properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    property_id INTEGER,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id),
    FOREIGN KEY(property_id) REFERENCES properties(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS property_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER,
    property_id INTEGER,
    FOREIGN KEY(tenant_id) REFERENCES tenants(id),
    FOREIGN KEY(property_id) REFERENCES properties(id)
  )`);
});

// Helper function to run database queries
function runQuery(query, params = []) {
  return new Promise((resolve, reject) => {
    db.all(query, params, (error, rows) => {
      if (error) {
        reject(error);
      } else {
        const result = rows.map(row => ({ ...row }));
        resolve(result);
      }
    });
  });
}

// Helper function to generate the JWT token
function generateToken(payload) {
  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
}

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    // split the token from the header
  const token = req.headers['authorization'].split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, secretKey, (error, decoded) => {
    if (error) {
      console.error(error);
      return res.status(401).json({ error: 'Invalid token' });
    }

    if (decoded.role === 'tenant') {
    req.tenant = decoded;
    } else if (decoded.role === 'landlord') {
    req.landlord = decoded;
    }
    next();
  });
}

// Landlord sign up
app.post('/api/landlords/signup', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  try {
    // Check if landlord with the same email already exists
    const existingLandlord = await runQuery('SELECT * FROM landlords WHERE email = ?', [email]);
    if (existingLandlord.length > 0) {
      return res.status(400).json({ error: 'Landlord with the same email already exists' });
    }

    // Encrypt the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Register the landlord in the database
    const result = await runQuery(
      'INSERT INTO landlords (first_name, last_name, email, password) VALUES (?, ?, ?, ?)',
      [first_name, last_name, email, hashedPassword]
    );

    // Generate token
    const token = generateToken({ id: result.lastID, role: 'landlord' });

    res.json({ message: 'Landlord signed up successfully', landlord_id: result.lastID, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord login
app.post('/api/landlords/login', (req, res) => {
  const { email, password } = req.body;

  // Find the landlord by email
  db.get('SELECT * FROM landlords WHERE email = ?', [email], async (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if the password matches
    const passwordMatches = await bcrypt.compare(password, row.password);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create and return JWT token
    const token = jwt.sign({ id: row.id, role: 'landlord' }, secretKey, { expiresIn: '1h' });

    res.json({ message: 'Landlord logged in successfully', landlord_id: row.id, token });
  });
});

// Landlord create a property
app.post('/api/properties', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { title, description, address, rent_fee, availability, image } = req.body;
  const landlord_id = req.landlord.id;

  try {
    const result = await runQuery(
      'INSERT INTO properties (landlord_id, title, description, address, rent_fee, availability, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [landlord_id, title, description, address, rent_fee, availability, image]
    );

    res.json({ message: 'Property created successfully', property_id: result.lastID });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord update a property
app.put('/api/properties/:property_id', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { property_id } = req.params;
  const { title, description, address, rent_fee, availability, image } = req.body;
  const landlord_id = req.landlord.id;

  try {
    const propertyResult = await runQuery('SELECT * FROM properties WHERE id = ?', [property_id]);

    if (propertyResult.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }

    if (propertyResult[0].landlord_id !== landlord_id) {
      return res.status(403).json({ error: 'Not authorized to update this property' });
    }

    await runQuery(
      'UPDATE properties SET title = ?, description = ?, address = ?, rent_fee = ?, availability =?, image = ? WHERE id = ?',
      [title, description, address, rent_fee, availability, image, property_id]
    );

    res.json({ message: 'Property updated successfully', property_id: propertyResult[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord delete a property
app.delete('/api/properties/:property_id', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { property_id } = req.params;
  const landlord_id = req.landlord.id;

  try {
    const propertyResult = await runQuery('SELECT * FROM properties WHERE id = ?', [property_id]);

    if (propertyResult.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }

    if (propertyResult[0].landlord_id !== landlord_id) {
      return res.status(403).json({ error: 'Not authorized to delete this property' });
    }

    await runQuery('DELETE FROM properties WHERE id = ?', [property_id]);

    res.json({ message: 'Property deleted successfully', property_id: propertyResult[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord make a property available
app.put('/api/properties/:property_id/availability', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { property_id } = req.params;
  const landlord_id = req.landlord.id;

  try {
    const propertyResult = await runQuery('SELECT * FROM properties WHERE id = ?', [property_id]);

    if (propertyResult.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }

    if (propertyResult[0].landlord_id !== landlord_id) {
      return res.status(403).json({ error: 'Not authorized to update availability for this property' });
    }

    await runQuery(
      'UPDATE properties SET availability = 1 WHERE id = ?',
      [property_id]
    );

    res.json({ message: 'Property availability updated successfully', property_id: propertyResult[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord approve a tenant's request to move in
app.post('/api/properties/:property_id/approve', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { property_id } = req.params;
  const { tenant_id } = req.body;
  const landlord_id = req.landlord.id;

  try {
    const propertyResult = await runQuery('SELECT * FROM properties WHERE id = ?', [property_id]);

    if (propertyResult.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }

    if (propertyResult[0].landlord_id !== landlord_id) {
      return res.status(403).json({ error: 'Not authorized to approve requests for this property' });
    }

    const requestResult = await runQuery(
      'SELECT * FROM property_requests WHERE property_id = ? AND tenant_id = ?',
      [property_id, tenant_id]
    );

    if (requestResult.length === 0) {
      return res.status(404).json({ error: 'Property request not found', result: requestResult });
    }

    await runQuery('DELETE FROM property_requests WHERE id = ?', [requestResult[0].id]);

    await runQuery(
      'INSERT INTO tenant_properties (tenant_id, property_id) VALUES (?, ?)',
      [tenant_id, property_id]
    );

    res.json({ message: 'Request approved successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/api/tenants/approved_properties', verifyToken, async (req, res) => {
  if (!req.tenant) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const tenant_id = req.tenant.id;

  try {
    const properties = await runQuery(`
      SELECT tp.*, p.title AS property_title, p.description AS property_description,
      p.address AS property_address, p.rent_fee AS property_rent_fee, p.availability AS property_availability,
      l.first_name AS landlord_first_name, l.last_name AS landlord_last_name
      FROM tenant_properties tp
      JOIN properties p ON tp.property_id = p.id
      JOIN landlords l ON p.landlord_id = l.id
      WHERE tp.tenant_id = ?
    `, [tenant_id]);

    res.json(properties);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});


app.get('/api/landlords/requests_to_approve', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const landlord_id = req.landlord.id;

  try {
    const requests = await runQuery(`
      SELECT r.*, t.first_name AS tenant_first_name, t.last_name AS tenant_last_name,
      p.id AS property_id, p.title AS property_title, p.description AS property_description,
      p.address AS property_address, p.rent_fee AS property_rent_fee, p.availability AS property_availability
      FROM property_requests r
      JOIN tenants t ON r.tenant_id = t.id
      JOIN properties p ON r.property_id = p.id
      WHERE p.landlord_id = ?
    `, [landlord_id]);

    res.json(requests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});


app.get('/api/landlords/approved_requests', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const landlord_id = req.landlord.id;

  try {
    const approvedRequests = await runQuery(`
      SELECT tp.*, t.first_name AS tenant_first_name, t.last_name AS tenant_last_name,
      p.id AS property_id, p.title AS property_title, p.description AS property_description,
      p.address AS property_address, p.rent_fee AS property_rent_fee, p.availability AS property_availability
      FROM tenant_properties tp
      JOIN tenants t ON tp.tenant_id = t.id
      JOIN properties p ON tp.property_id = p.id
      WHERE p.landlord_id = ?
    `, [landlord_id]);

    res.json(approvedRequests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});


// Tenant sign up
app.post('/api/tenants/signup', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  try {
    // Check if tenant with the same email already exists
    const existingTenant = await runQuery('SELECT * FROM tenants WHERE email = ?', [email]);
    if (existingTenant.length > 0) {
      return res.status(400).json({ error: 'Tenant with the same email already exists' });
    }

    // Encrypt the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Register the tenant in the database
    const result = await runQuery(
      'INSERT INTO tenants (first_name, last_name, email, password) VALUES (?, ?, ?, ?)',
      [first_name, last_name, email, hashedPassword]
    );

    // Generate token
    const token = generateToken({ id: result.lastID, role: 'tenant' });

    res.json({ message: 'Tenant signed up successfully', tenant_id: result.lastID, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Tenant login
app.post('/api/tenants/login', (req, res) => {
  const { email, password } = req.body;

  // Find the tenant by email
  db.get('SELECT * FROM tenants WHERE email = ?', [email], async (error, row) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if the password matches
    const passwordMatches = await bcrypt.compare(password, row.password);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create and return JWT token
    const token = jwt.sign({ id: row.id, role: 'tenant' }, secretKey, { expiresIn: '1h' });

    res.json({ message: 'Tenant logged in successfully', tenant_id: row.id, token });
  });
});

// Tenant request to move into a property
app.post('/api/properties/:property_id/request', verifyToken, async (req, res) => {
  if (!req.tenant) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { property_id } = req.params;
  const tenant_id = req.tenant.id;

  try {
    const propertyResult = await runQuery('SELECT * FROM properties WHERE id = ?', [property_id]);

    if (propertyResult.length === 0) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const requestResult = await runQuery(
      'SELECT * FROM property_requests WHERE property_id = ? AND tenant_id = ?',
      [property_id, tenant_id]
    );

    if (requestResult.length > 0) {
      return res.status(400).json({ error: 'Request already sent for this property' });
    }

    await runQuery(
      'INSERT INTO property_requests (tenant_id, property_id) VALUES (?, ?)',
      [tenant_id, property_id]
    );

    res.json({ message: 'Request sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Tenant view all available properties
app.get('/api/properties', async (req, res) => {

  try {
    
    const properties = await runQuery('SELECT * FROM properties');
    res.json(properties);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Endpoint to get a single available property by ID
app.get('/api/properties/:property_id', async (req, res) => {
    const { property_id } = req.params;
  
    try {
      const property = await runQuery('SELECT * FROM properties WHERE id = ? AND availability = 1', [property_id]);
  
      if (property.length === 0) {
        return res.status(404).json({ error: 'Property not found or not available' });
      }
  
      res.json(property[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred' });
    }
  });

  // Tenant profile
app.get('/api/tenants/profile', verifyToken, async (req, res) => {
  if (!req.tenant) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const tenant = await runQuery('SELECT * FROM tenants WHERE id = ?', [req.tenant.id]);

    if (tenant.length === 0) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    res.json(tenant[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Tenant update profile
app.put('/api/tenants/update_profile', verifyToken, async (req, res) => {
  if (!req.tenant) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { first_name, last_name, email } = req.body;
  const tenant_id = req.tenant.id;

  try {
    const existingTenant = await runQuery('SELECT * FROM tenants WHERE email = ? AND id != ?', [email, tenant_id]);

    if (existingTenant.length > 0) {
      return res.status(400).json({ error: 'Tenant with the same email already exists' });
    }

    await runQuery('UPDATE tenants SET first_name = ?, last_name = ?, email = ? WHERE id = ?', [
      first_name,
      last_name,
      email,
      tenant_id
    ]);

    res.json({ message: 'Tenant profile updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Tenant delete profile
app.delete('/api/tenants/delete_profile', verifyToken, async (req, res) => {
  if (!req.tenant) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const tenant_id = req.tenant.id;

  try {
    await runQuery('DELETE FROM tenants WHERE id = ?', [tenant_id]);

    res.json({ message: 'Tenant profile deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord profile
app.get('/api/landlords/profile', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const landlord = await runQuery('SELECT * FROM landlords WHERE id = ?', [req.landlord.id]);

    if (landlord.length === 0) {
      return res.status(404).json({ error: 'Landlord not found' });
    }

    res.json(landlord[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord update profile
app.put('/api/landlords/update_profile', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { first_name, last_name, email } = req.body;
  const landlord_id = req.landlord.id;

  try {
    const existingLandlord = await runQuery('SELECT * FROM landlords WHERE email = ? AND id != ?', [
      email,
      landlord_id
    ]);

    if (existingLandlord.length > 0) {
      return res.status(400).json({ error: 'Landlord with the same email already exists' });
    }

    await runQuery('UPDATE landlords SET first_name = ?, last_name = ?, email = ? WHERE id = ?', [
      first_name,
      last_name,
      email,
      landlord_id
    ]);

    res.json({ message: 'Landlord profile updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Landlord delete profile
app.delete('/api/landlords/delete_profile', verifyToken, async (req, res) => {
  if (!req.landlord) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const landlord_id = req.landlord.id;

  try {
    await runQuery('DELETE FROM landlords WHERE id = ?', [landlord_id]);

    res.json({ message: 'Landlord profile deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred' });
  }
});

  

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
