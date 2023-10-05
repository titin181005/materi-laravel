@extends('template.master')

@section('content')

  <!-- Content Wrapper. Contains page content -->
  <div class="content-wrapper">
    <!-- Content Header (Page header) -->
    <section class="content-header">
      <div class="container-fluid">
        <div class="row mb-2">
          <div class="col-sm-6">
            <h1>Data Genre</h1>
          </div>
        </div>
      </div><!-- /.container-fluid -->
    </section>

    <!-- Main content -->
    <section class="content">
      <div class="container-fluid">
        <div class="row">
          <!-- left column -->
          <div class="col-md-12">
            <!-- general form elements -->
            <div class="card card-primary">
              <div class="card-header">
                <h3 class="card-title">Data Genre</h3>
              </div>
              <!-- /.card-header -->
              <!-- form start -->
              <form action="{{ route('genre.store') }}" method="POST">
                @csrf
                <div class="card-body">
                  <div class="form-group">
                    <label for="nama">Nama</label>
                    <input type="text" name="nama" class="form-control @error('nama') is-invalid @enderror" id="nama" placeholder="Enter Nama Anda" value="{{ old('nama') }}">
                </div>
                @error('nama') 
                <div class="alert alert-danger">{{ $message }}</div>
                @enderror
            
            
            
                <!-- /.card-body -->

                <div class="card-footer">
                  <button type="submit" class="btn btn-info">Submit</button>
                  <button type="reset" class="btn btn-info">Reset</button>
                  <a href="{{ route('genre.index') }}" class="btn btn-info">Kembali</a>
              </form>
          </div>
          </div>
            <!-- /.card -->

          
          </div>
          <!--/.col (left) -->
        </div>
        <!-- /.row -->
      </div><!-- /.container-fluid -->
    </section>
    <!-- /.content -->
  </div>
  <!-- /.content-wrapper -->

@endsection